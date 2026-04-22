import os, io, hashlib, math, struct, threading, time, json, base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from collections import Counter

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ══════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════
BG      = "#0b0f19"
PANEL   = "#111827"
PANEL2  = "#0f172a"
TEXT    = "#e5e7eb"
ACCENT  = "#38bdf8"
GREEN   = "#22c55e"
RED     = "#ef4444"
YELLOW  = "#f59e0b"
MUTED   = "#94a3b8"
PURPLE  = "#a78bfa"
ORANGE  = "#fb923c"
TEAL    = "#2dd4bf"

# ══════════════════════════════════════════════
#  FILE SIGNATURES  (9 types)
# ══════════════════════════════════════════════
file_signatures = {
    "jpg":  {"header": b'\xff\xd8\xff',           "footer": b'\xff\xd9'},
    "png":  {"header": b'\x89PNG\r\n\x1a\n',      "footer": b'IEND\xaeB`\x82'},
    "pdf":  {"header": b'%PDF',                   "footer": b'%%EOF'},
    "gif":  {"header": b'GIF8',                   "footer": b'\x00\x3b'},
    "bmp":  {"header": b'BM',                     "footer": None},
    "zip":  {"header": b'PK\x03\x04',             "footer": b'PK\x05\x06'},
    "mp3":  {"header": b'\xff\xfb',               "footer": None},
    "docx": {"header": b'PK\x03\x04',             "footer": b'PK\x05\x06'},
    "rar":  {"header": b'Rar!\x1a\x07',           "footer": None},
}

TYPE_COLOR = {
    "jpg": GREEN, "png": ACCENT, "pdf": RED,
    "gif": YELLOW, "bmp": ORANGE, "zip": PURPLE,
    "mp3": "#ec4899", "docx": TEAL, "rar": "#f97316"
}

type_vars    = {}
selected_file = ""
output_dir    = "recovered_files"
recovered_files = []
scan_running  = False
scan_start_time = None
stat_labels   = {}
timeline_items = []

# ══════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════
def compute_hashes(data):
    return (hashlib.md5(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.sha256(data).hexdigest())

def compute_entropy(data):
    if not data: return 0.0
    counts = Counter(data)
    t = len(data)
    return round(-sum((c/t)*math.log2(c/t) for c in counts.values()), 2)

def entropy_label(e):
    if e >= 7.5: return "ENCRYPTED/COMPRESSED", RED
    if e >= 6.0: return "HIGH ENTROPY",         YELLOW
    if e >= 4.0: return "NORMAL",               GREEN
    return "LOW ENTROPY", MUTED

def hex_dump(data, n=256):
    lines = []
    for i in range(0, min(n, len(data)), 16):
        chunk = data[i:i+16]
        hp    = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ap    = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
        lines.append(f"{i:04X}  {hp}  {ap}")
    return "\n".join(lines)

def fmt_size(n):
    for u in ("B","KB","MB","GB"):
        if n<1024: return f"{n:.1f} {u}"
        n/=1024
    return f"{n:.1f} TB"

def log(msg, color=None):
    tag = color or TEXT
    log_box.insert(tk.END, msg+"\n", tag)
    log_box.tag_config(tag, foreground=tag)
    log_box.see(tk.END)

def clear_logs():
    log_box.delete(1.0, tk.END)

def update_stats():
    counts     = Counter(r["ftype"] for r in recovered_files)
    total_size = sum(r["size"] for r in recovered_files)
    stat_labels["total"].config(text=f"TOTAL: {len(recovered_files)}")
    stat_labels["size"].config(text=f"SIZE: {fmt_size(total_size)}")
    for ft in ["jpg","png","pdf","gif","bmp","zip","mp3","docx","rar"]:
        if ft in stat_labels:
            stat_labels[ft].config(text=f"{ft.upper()}: {counts.get(ft,0)}")

# ══════════════════════════════════════════════
#  BROWSE
# ══════════════════════════════════════════════
def browse_file():
    global selected_file
    path = filedialog.askopenfilename(
        title="Select disk image",
        filetypes=[("Disk Images","*.img *.dd *.bin *.raw *.001 *.e01"),
                   ("All files","*.*")])
    if path:
        selected_file = path
        short = os.path.basename(path)
        file_label.config(text=short if len(short)<36 else "…"+short[-33:])
        size_label.config(text=f"Size: {fmt_size(os.path.getsize(path))}")
        md5_label.config(text="MD5: —  (scan to compute)")

# ══════════════════════════════════════════════
#  PREVIEW (click on recovered file)
# ══════════════════════════════════════════════
def show_preview(event=None):
    sel = file_list.curselection()
    if not sel: return
    idx = sel[0]
    if idx >= len(recovered_files): return
    rec  = recovered_files[idx]
    path = rec["path"]
    ext  = rec["ftype"]

    hex_box.config(state=tk.NORMAL); hex_box.delete(1.0,tk.END)
    image_label.config(image="",text="")
    meta_box.config(state=tk.NORMAL); meta_box.delete(1.0,tk.END)

    with open(path,"rb") as f:
        data = f.read()

    # metadata tab
    elabel,ecolor = entropy_label(rec["entropy"])
    rows = [
        ("File",       os.path.basename(path)),
        ("Type",       ext.upper()),
        ("Size",       fmt_size(rec["size"])),
        ("Offset",     f"{rec['offset']:#x}  ({rec['offset']:,})"),
        ("Confidence", rec["confidence"]),
        ("MD5",        rec["md5"]),
        ("SHA1",       rec["sha1"]),
        ("SHA256",     rec["sha256"][:32]+"…"),
        ("Entropy",    f"{rec['entropy']}  [{elabel}]"),
        ("Magic",      rec.get("magic","—")),
        ("Recovered",  rec["timestamp"]),
    ]
    for k,v in rows:
        meta_box.insert(tk.END, f"  {k:<14}", ACCENT)
        col = ecolor if k=="Entropy" else (GREEN if k=="Confidence" and "HIGH" in v else TEXT)
        meta_box.insert(tk.END, f"{v}\n", col)
    meta_box.config(state=tk.DISABLED)

    # image preview
    if ext in ("jpg","png","gif","bmp") and PIL_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((290,185))
            photo = ImageTk.PhotoImage(img)
            image_label.config(image=photo,text="")
            image_label.image = photo
        except Exception as e:
            image_label.config(text=f"Preview error:\n{e}", fg=RED)
    elif ext in ("jpg","png","gif","bmp"):
        image_label.config(text="pip install pillow\nfor image preview", fg=YELLOW)
    else:
        icons = {"zip":"[ZIP ARCHIVE]","mp3":"[AUDIO FILE]",
                 "pdf":"[PDF DOCUMENT]","docx":"[WORD DOCUMENT]",
                 "rar":"[RAR ARCHIVE]"}
        image_label.config(text=icons.get(ext,f"[{ext.upper()} FILE]"),
                           fg=TYPE_COLOR.get(ext,TEXT))

    # hex dump
    hex_box.insert(tk.END, hex_dump(data, 512))
    hex_box.config(state=tk.DISABLED)
    nb.select(1)

# ══════════════════════════════════════════════
#  MAGIC BYTE IDENTIFIER
# ══════════════════════════════════════════════
MAGIC_MAP = {
    b'\xff\xd8\xff':           "JPEG Image",
    b'\x89PNG':                "PNG Image",
    b'%PDF':                   "PDF Document",
    b'GIF8':                   "GIF Image",
    b'BM':                     "BMP Image",
    b'PK\x03\x04':             "ZIP / Office Archive",
    b'Rar!\x1a\x07':           "RAR Archive",
    b'\xff\xfb':               "MP3 Audio",
    b'ID3':                    "MP3 with ID3 tag",
    b'\x1f\x8b':               "GZIP Archive",
    b'7z\xbc\xaf':             "7-Zip Archive",
    b'\x00\x00\x00\x0cftyp':  "MP4 Video",
    b'RIFF':                   "WAV/AVI File",
    b'\xd0\xcf\x11\xe0':       "MS Office (old)",
    b'OggS':                   "OGG Audio",
    b'\x7fELF':                "ELF Executable",
    b'MZ':                     "Windows EXE/DLL",
    b'\xca\xfe\xba\xbe':       "Java Class",
    b'SQLite':                 "SQLite Database",
}

def identify_magic(data):
    for sig, name in MAGIC_MAP.items():
        if data[:len(sig)] == sig:
            return name
    return "Unknown"

# ══════════════════════════════════════════════
#  BYTE FREQUENCY VIEWER
# ══════════════════════════════════════════════
def show_byte_freq():
    sel = file_list.curselection()
    if not sel:
        messagebox.showinfo("Select file","Click a recovered file first."); return
    idx = sel[0]
    if idx >= len(recovered_files): return
    rec = recovered_files[idx]
    with open(rec["path"],"rb") as f:
        data = f.read()

    counts = Counter(data)
    top20  = counts.most_common(20)

    win = tk.Toplevel(root)
    win.title(f"Byte Frequency — {os.path.basename(rec['path'])}")
    win.configure(bg=BG)
    win.geometry("520x420")

    tk.Label(win, text="TOP 20 BYTE VALUES", bg=BG, fg=ACCENT,
             font=("Consolas",10,"bold")).pack(pady=(12,6))

    canvas = tk.Canvas(win, bg=PANEL2, relief=tk.FLAT,
                       width=490, height=320)
    canvas.pack(padx=14, pady=4)

    max_count = top20[0][1] if top20 else 1
    bar_w = 22
    gap   = 2
    base_y = 300

    for i,(byte_val, count) in enumerate(top20):
        bar_h = int((count/max_count)*240)
        x0 = 10 + i*(bar_w+gap)
        x1 = x0 + bar_w
        y0 = base_y - bar_h
        y1 = base_y
        # gradient-like using two rects
        canvas.create_rectangle(x0,y0,x1,y1, fill=ACCENT, outline="")
        canvas.create_text(x0+bar_w//2, base_y+10,
                           text=f"{byte_val:02X}", fill=MUTED,
                           font=("Consolas",7), angle=0)
        canvas.create_text(x0+bar_w//2, y0-8,
                           text=str(count), fill=TEXT,
                           font=("Consolas",6))

    tk.Label(win, text=f"Total bytes: {len(data):,}  |  Unique values: {len(counts)}",
             bg=BG, fg=MUTED, font=("Consolas",8)).pack(pady=4)

# ══════════════════════════════════════════════
#  STRING EXTRACTOR
# ══════════════════════════════════════════════
def extract_strings():
    sel = file_list.curselection()
    if not sel:
        messagebox.showinfo("Select file","Click a recovered file first."); return
    idx = sel[0]
    if idx >= len(recovered_files): return
    rec = recovered_files[idx]

    with open(rec["path"],"rb") as f:
        data = f.read()

    # extract printable ASCII strings >= 5 chars
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= 5:
                strings.append("".join(current))
            current = []
    if len(current) >= 5:
        strings.append("".join(current))

    win = tk.Toplevel(root)
    win.title(f"Strings — {os.path.basename(rec['path'])}")
    win.configure(bg=BG)
    win.geometry("620x500")

    tk.Label(win, text=f"EXTRACTED STRINGS  ({len(strings)} found)",
             bg=BG, fg=ACCENT, font=("Consolas",10,"bold")).pack(pady=(12,4))

    frame = tk.Frame(win, bg=BG)
    frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

    sb = tk.Scrollbar(frame)
    sb.pack(side=tk.RIGHT, fill=tk.Y)

    txt = tk.Text(frame, bg=PANEL2, fg=GREEN, font=("Consolas",9),
                  relief=tk.FLAT, padx=8, pady=6,
                  yscrollcommand=sb.set, wrap=tk.NONE)
    sb.config(command=txt.yview)
    txt.pack(fill=tk.BOTH, expand=True)

    for s in strings[:500]:  # cap at 500
        txt.insert(tk.END, s+"\n")
    txt.config(state=tk.DISABLED)

    tk.Label(win, text="Showing first 500 strings (min length 5)",
             bg=BG, fg=MUTED, font=("Consolas",8)).pack(pady=4)

# ══════════════════════════════════════════════
#  COMPARE FILES (hash diff)
# ══════════════════════════════════════════════
def compare_files():
    if len(recovered_files) < 2:
        messagebox.showinfo("Need 2 files","Recover at least 2 files first."); return

    win = tk.Toplevel(root)
    win.title("Compare Files")
    win.configure(bg=BG)
    win.geometry("600x420")

    tk.Label(win, text="FILE COMPARISON", bg=BG, fg=ACCENT,
             font=("Consolas",11,"bold")).pack(pady=(12,8))

    names = [os.path.basename(r["path"]) for r in recovered_files]

    row1 = tk.Frame(win, bg=BG); row1.pack(fill=tk.X, padx=20, pady=4)
    tk.Label(row1, text="File A:", bg=BG, fg=MUTED, font=("Consolas",9), width=8).pack(side=tk.LEFT)
    var_a = tk.StringVar(value=names[0])
    ttk.Combobox(row1, textvariable=var_a, values=names, width=40,
                 font=("Consolas",9)).pack(side=tk.LEFT)

    row2 = tk.Frame(win, bg=BG); row2.pack(fill=tk.X, padx=20, pady=4)
    tk.Label(row2, text="File B:", bg=BG, fg=MUTED, font=("Consolas",9), width=8).pack(side=tk.LEFT)
    var_b = tk.StringVar(value=names[1])
    ttk.Combobox(row2, textvariable=var_b, values=names, width=40,
                 font=("Consolas",9)).pack(side=tk.LEFT)

    res_box = tk.Text(win, bg=PANEL2, fg=TEXT, font=("Consolas",9),
                      relief=tk.FLAT, padx=10, pady=8, height=14)
    res_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

    def do_compare():
        res_box.delete(1.0,tk.END)
        na,nb = var_a.get(), var_b.get()
        ra = next((r for r in recovered_files if os.path.basename(r["path"])==na),None)
        rb = next((r for r in recovered_files if os.path.basename(r["path"])==nb),None)
        if not ra or not rb: return

        def row(label, va, vb):
            match = va==vb
            c = GREEN if match else RED
            sym = "  ✔ MATCH" if match else "  ✗ DIFFER"
            res_box.insert(tk.END, f"  {label:<14}", ACCENT)
            res_box.insert(tk.END, f"{str(va)[:28]:<30}  {str(vb)[:28]:<30}{sym}\n", c)

        res_box.insert(tk.END, f"  {'FIELD':<14}{'FILE A':<30}  {'FILE B':<30}\n", MUTED)
        res_box.insert(tk.END, "  "+"-"*80+"\n", MUTED)
        row("Type",       ra["ftype"].upper(), rb["ftype"].upper())
        row("Size",       fmt_size(ra["size"]), fmt_size(rb["size"]))
        row("MD5",        ra["md5"][:16]+"…", rb["md5"][:16]+"…")
        row("SHA1",       ra["sha1"][:16]+"…", rb["sha1"][:16]+"…")
        row("Entropy",    ra["entropy"], rb["entropy"])
        row("Confidence", ra["confidence"], rb["confidence"])

        if ra["md5"]==rb["md5"]:
            res_box.insert(tk.END,"\n  ► Files are IDENTICAL (same MD5)\n", GREEN)
        else:
            res_box.insert(tk.END,"\n  ► Files are DIFFERENT\n", RED)

    tk.Button(win, text="Compare", command=do_compare,
              bg=ACCENT, fg="#0b0f19", font=("Consolas",10,"bold"),
              relief=tk.FLAT, pady=5, cursor="hand2").pack(pady=(0,8))

# ══════════════════════════════════════════════
#  EXPORT
# ══════════════════════════════════════════════
def export_html_report():
    if not recovered_files:
        messagebox.showwarning("No Data","Run a scan first."); return
    path = filedialog.asksaveasfilename(
        defaultextension=".html", filetypes=[("HTML","*.html")],
        initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    if not path: return

    rows=""
    for i,r in enumerate(recovered_files):
        el,_=entropy_label(r["entropy"])
        cc="#22c55e" if "HIGH" in r["confidence"] else "#f59e0b"
        rows+=(f"<tr><td>{i+1}</td>"
               f"<td style='color:{TYPE_COLOR.get(r[\"ftype\"],\"#e5e7eb\")}'>{r['ftype'].upper()}</td>"
               f"<td>{os.path.basename(r['path'])}</td>"
               f"<td>{r['offset']:#x}</td><td>{fmt_size(r['size'])}</td>"
               f"<td style='color:{cc}'>{r['confidence']}</td>"
               f"<td>{r['entropy']} ({el})</td>"
               f"<td style='font-size:10px'>{r['md5']}</td>"
               f"<td>{r.get('magic','—')}</td>"
               f"<td>{r['timestamp']}</td></tr>\n")

    html=(f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Forensic Report — MUET</title>"
          f"<style>body{{background:#0b0f19;color:#e5e7eb;font-family:Consolas,monospace;padding:20px}}"
          f"h1{{color:#38bdf8}}h2{{color:#94a3b8;font-size:13px}}"
          f"table{{border-collapse:collapse;width:100%;font-size:12px}}"
          f"th{{background:#111827;color:#38bdf8;padding:8px;text-align:left;border-bottom:1px solid #1e293b}}"
          f"td{{padding:6px 8px;border-bottom:1px solid #111827}}"
          f"tr:hover td{{background:#111827}}</style></head><body>"
          f"<h1>&#128269; Forensic Carving Report</h1>"
          f"<h2>Mehran University of Engineering &amp; Technology — Jamshoro</h2>"
          f"<h2>Image: {selected_file} | Date: {datetime.now()} | Files: {len(recovered_files)}</h2>"
          f"<table><tr><th>#</th><th>Type</th><th>Filename</th><th>Offset</th>"
          f"<th>Size</th><th>Confidence</th><th>Entropy</th><th>MD5</th><th>Magic</th><th>Recovered</th></tr>"
          f"{rows}</table></body></html>")

    with open(path,"w") as f: f.write(html)
    log(f"[✔] HTML report: {path}", GREEN)
    messagebox.showinfo("Exported",f"Report saved:\n{path}")


def export_csv():
    if not recovered_files:
        messagebox.showwarning("No Data","Run a scan first."); return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV","*.csv")],
        initialfile=f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    if not path: return
    with open(path,"w") as f:
        f.write("No,Type,Filename,Offset_Dec,Offset_Hex,Size_Bytes,Confidence,Entropy,Magic,MD5,SHA1,SHA256,Timestamp\n")
        for i,r in enumerate(recovered_files):
            f.write(f"{i+1},{r['ftype'].upper()},{os.path.basename(r['path'])},"
                    f"{r['offset']},{r['offset']:#x},{r['size']},"
                    f"{r['confidence']},{r['entropy']},{r.get('magic','—')},"
                    f"{r['md5']},{r['sha1']},{r['sha256']},{r['timestamp']}\n")
    log(f"[✔] CSV exported: {path}", GREEN)
    messagebox.showinfo("Exported",f"CSV saved:\n{path}")


def export_json():
    if not recovered_files:
        messagebox.showwarning("No Data","Run a scan first."); return
    path = filedialog.asksaveasfilename(
        defaultextension=".json", filetypes=[("JSON","*.json")],
        initialfile=f"forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    if not path: return
    data = []
    for r in recovered_files:
        d = dict(r)
        d["path"] = os.path.abspath(d["path"])
        data.append(d)
    with open(path,"w") as f:
        json.dump({"image":selected_file,"date":str(datetime.now()),
                   "total":len(recovered_files),"files":data}, f, indent=2)
    log(f"[✔] JSON exported: {path}", GREEN)
    messagebox.showinfo("Exported",f"JSON saved:\n{path}")


def open_output_folder():
    if os.path.exists(output_dir):
        if os.name=="nt": os.startfile(output_dir)
        else: os.system(f"xdg-open {output_dir}")
    else:
        messagebox.showinfo("Not found","No recovered_files folder yet.")


def delete_selected():
    sel = file_list.curselection()
    if not sel: return
    idx = sel[0]
    if idx>=len(recovered_files): return
    rec = recovered_files[idx]
    if messagebox.askyesno("Delete",f"Delete {os.path.basename(rec['path'])}?"):
        try: os.remove(rec["path"])
        except: pass
        recovered_files.pop(idx)
        file_list.delete(idx)
        update_stats()
        image_label.config(image="",text="")
        hex_box.config(state=tk.NORMAL); hex_box.delete(1.0,tk.END); hex_box.config(state=tk.DISABLED)
        meta_box.config(state=tk.NORMAL); meta_box.delete(1.0,tk.END); meta_box.config(state=tk.DISABLED)
        log(f"[-] Deleted {os.path.basename(rec['path'])}", YELLOW)

# ══════════════════════════════════════════════
#  SEARCH / FILTER
# ══════════════════════════════════════════════
def filter_list(*args):
    q   = search_var.get().lower()
    flt = filter_var.get()
    file_list.delete(0,tk.END)
    for r in recovered_files:
        name = os.path.basename(r["path"])
        if q and q not in name.lower(): continue
        if flt!="ALL" and r["ftype"].upper()!=flt: continue
        file_list.insert(tk.END, name)
        file_list.itemconfig(tk.END, fg=TYPE_COLOR.get(r["ftype"],TEXT))

# ══════════════════════════════════════════════
#  CORE CARVING ENGINE  (threaded)
# ══════════════════════════════════════════════
def start_recovery():
    global scan_running, scan_start_time
    if scan_running:
        messagebox.showinfo("Busy","Scan already running."); return
    if not selected_file:
        messagebox.showerror("Error","Select a disk image first."); return
    targets = [ft for ft,var in type_vars.items() if var.get()]
    if not targets:
        messagebox.showwarning("No Targets","Enable at least one file type."); return
    scan_running = True
    scan_start_time = time.time()
    start_btn.config(state=tk.DISABLED, text="  SCANNING…")
    threading.Thread(target=_scan_thread, args=(targets,), daemon=True).start()
    _update_timer()

def _update_timer():
    if scan_running:
        elapsed = time.time() - scan_start_time
        timer_label.config(text=f"⏱ {elapsed:.1f}s")
        root.after(100, _update_timer)
    else:
        elapsed = time.time() - (scan_start_time or time.time())
        timer_label.config(text=f"⏱ {elapsed:.1f}s")

def _scan_thread(targets):
    global recovered_files, scan_running
    recovered_files = []
    root.after(0, lambda: file_list.delete(0,tk.END))
    root.after(0, lambda: image_label.config(image="",text=""))

    try:
        with open(selected_file,"rb") as f:
            data = f.read()
    except Exception as e:
        root.after(0, lambda: log(f"[!] Cannot read: {e}", RED))
        scan_running = False
        root.after(0, lambda: start_btn.config(state=tk.NORMAL, text="▶  START RECOVERY"))
        return

    total = len(data)
    img_md5 = hashlib.md5(data).hexdigest()
    root.after(0, lambda: progress.config(maximum=total, value=0))
    root.after(0, lambda: md5_label.config(text=f"MD5: {img_md5[:24]}…"))
    root.after(0, lambda: log(f"\n[*] {os.path.basename(selected_file)}  ({fmt_size(total)})", ACCENT))
    root.after(0, lambda: log(f"[*] Image MD5: {img_md5}", MUTED))
    root.after(0, lambda: log(f"[*] Targets: {', '.join(t.upper() for t in targets)}", MUTED))

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_count = 0
    report     = []

    for ftype in targets:
        if ftype not in file_signatures: continue
        sig    = file_signatures[ftype]
        header = sig["header"]
        footer = sig["footer"]
        start  = 0
        found  = 0

        root.after(0, lambda ft=ftype: log(f"\n[~] {ft.upper()} …", MUTED))

        while True:
            start_index = data.find(header, start)
            if start_index == -1: break

            if footer is None:
                if ftype=="bmp" and start_index+6<=total:
                    bmp_size  = struct.unpack_from("<I",data,start_index+2)[0]
                    end_index = min(start_index+bmp_size,total)
                    confidence="HIGH"; status=GREEN
                else:
                    end_index=min(start_index+500_000,total)
                    confidence="MEDIUM"; status=YELLOW
            elif ftype=="pdf":
                lim=start_index+10_000_000
                end_index=data.find(footer,start_index+len(header),lim)
                if end_index==-1:
                    end_index=data.find(b'%EOF',start_index+len(header),lim)
                if end_index==-1:
                    end_index=min(lim,total); confidence="LOW"; status=YELLOW
                else:
                    end_index+=len(footer)+2; end_index=min(end_index,total)
                    confidence="HIGH"; status=GREEN
            else:
                end_index=data.find(footer,start_index+len(header))
                if end_index==-1:
                    end_index=min(start_index+2_000_000,total)
                    confidence="LOW"; status=YELLOW
                else:
                    end_index+=len(footer); confidence="HIGH"; status=GREEN

            file_data = data[start_index:end_index]
            md5,sha1,sha256 = compute_hashes(file_data)
            entropy   = compute_entropy(file_data)
            magic     = identify_magic(file_data)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            filename  = f"{output_dir}/file_{file_count:04d}.{ftype}"

            with open(filename,"wb") as f:
                f.write(file_data)

            rec = dict(path=filename, ftype=ftype, offset=start_index,
                       size=len(file_data), md5=md5, sha1=sha1, sha256=sha256,
                       entropy=entropy, confidence=confidence,
                       magic=magic, timestamp=timestamp)
            recovered_files.append(rec)

            def _ui(r=rec, s=status):
                name=os.path.basename(r["path"])
                file_list.insert(tk.END,name)
                file_list.itemconfig(tk.END,fg=s)
                update_stats()

            elabel,_=entropy_label(entropy)
            root.after(0,_ui)
            root.after(0, lambda r=rec,s=status: log(
                f"[+] {os.path.basename(r['path'])}  {r['offset']:#x}  "
                f"{fmt_size(r['size'])}  {r['confidence']}  ENT:{r['entropy']}  {r['magic']}", s))
            root.after(0, lambda m=md5: log(f"    MD5 {m}", MUTED))

            report.append(
                f"{ftype.upper()}|{start_index}|{start_index:#x}|{len(file_data)}|"
                f"{confidence}|{entropy}|{magic}|{md5}|{sha1}|{filename}"
            )

            file_count+=1; found+=1; start=end_index
            root.after(0, lambda v=start_index: progress.config(value=v))

        root.after(0, lambda ft=ftype,n=found: log(f"[=] {ft.upper()}: {n} found", ACCENT))

    elapsed = round(time.time()-scan_start_time, 2)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    rpt = f"report_{ts}.txt"
    with open(rpt,"w") as f:
        f.write(f"Forensic Carving Report — MUET Jamshoro\n"
                f"Image:{selected_file}\nMD5:{img_md5}\nDate:{datetime.now()}\n"
                f"Total:{file_count}\nElapsed:{elapsed}s\n"+"="*70+"\n"
                "Type|Offset|Hex|Size|Confidence|Entropy|Magic|MD5|SHA1|File\n"
                +"\n".join(report))

    root.after(0, lambda: progress.config(value=total))
    root.after(0, lambda n=file_count,e=elapsed: log(
        f"\n[✔] Done — {n} file(s) in {e}s", GREEN))
    root.after(0, lambda: log(f"[📄] Report: {rpt}", ACCENT))
    root.after(0, lambda: start_btn.config(state=tk.NORMAL, text="▶  START RECOVERY"))
    root.after(0, update_stats)
    scan_running = False

# ══════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════
root = tk.Tk()
root.title("Digital Forensic File Carver  v4.0  —  MUET Jamshoro")
root.geometry("1420x820")
root.configure(bg=BG)
root.resizable(True,True)

# ── Window icon (MUET logo) ──
LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "muet_logo.png")
muet_photo_icon = None
muet_photo_title = None
if PIL_AVAILABLE and os.path.exists(LOGO_PATH):
    try:
        _ico = Image.open(LOGO_PATH).convert("RGBA").resize((32,32), Image.LANCZOS)
        muet_photo_icon = ImageTk.PhotoImage(_ico)
        root.iconphoto(True, muet_photo_icon)
    except: pass

style = ttk.Style()
style.theme_use("default")
style.configure("TProgressbar", troughcolor=PANEL2, background=ACCENT, thickness=5)
style.configure("TNotebook",       background=BG, borderwidth=0)
style.configure("TNotebook.Tab",   background=PANEL2, foreground=MUTED,
                font=("Consolas",9), padding=[10,4])
style.map("TNotebook.Tab",
          background=[("selected",PANEL)],
          foreground=[("selected",ACCENT)])
style.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2,
                foreground=TEXT, selectbackground=PANEL2)

# ── TOP BAR ──────────────────────────────────
topbar = tk.Frame(root, bg=PANEL2, height=40)
topbar.pack(side=tk.TOP, fill=tk.X)
topbar.pack_propagate(False)

# MUET logo in topbar
if PIL_AVAILABLE and os.path.exists(LOGO_PATH):
    try:
        _logo32 = Image.open(LOGO_PATH).convert("RGBA").resize((30,30), Image.LANCZOS)
        muet_photo_title = ImageTk.PhotoImage(_logo32)
        logo_lbl = tk.Label(topbar, image=muet_photo_title, bg=PANEL2)
        logo_lbl.pack(side=tk.LEFT, padx=(10,4), pady=4)
    except: pass

tk.Label(topbar, text="MUET JAMSHORO  |  FORENSIC FILE CARVER v4.0",
         bg=PANEL2, fg=ACCENT, font=("Consolas",10,"bold")).pack(side=tk.LEFT, padx=6)

timer_label = tk.Label(topbar, text="⏱ 0.0s", bg=PANEL2, fg=YELLOW, font=("Consolas",9))
timer_label.pack(side=tk.RIGHT, padx=16)

for key,label,color in [
    ("total","TOTAL: 0",TEXT),("size","SIZE: 0 B",MUTED),
    ("jpg","JPG: 0",GREEN),("png","PNG: 0",ACCENT),("pdf","PDF: 0",RED),
    ("gif","GIF: 0",YELLOW),("bmp","BMP: 0",ORANGE),
    ("zip","ZIP: 0",PURPLE),("mp3","MP3: 0","#ec4899"),
    ("docx","DOCX: 0",TEAL),("rar","RAR: 0","#f97316"),
]:
    lbl=tk.Label(topbar,text=label,bg=PANEL2,fg=color,font=("Consolas",8))
    lbl.pack(side=tk.LEFT,padx=7)
    stat_labels[key]=lbl

# ── MAIN ─────────────────────────────────────
main = tk.Frame(root, bg=BG)
main.pack(fill=tk.BOTH, expand=True)

# ── LEFT PANEL ──────────────────────────────
left = tk.Frame(main, bg=PANEL, width=220)
left.pack(side=tk.LEFT, fill=tk.Y)
left.pack_propagate(False)

def sep():
    tk.Frame(left,bg="#1e293b",height=1).pack(fill=tk.X,padx=10,pady=5)

# MUET logo in left panel
if PIL_AVAILABLE and os.path.exists(LOGO_PATH):
    try:
        _logo64 = Image.open(LOGO_PATH).convert("RGBA").resize((64,64), Image.LANCZOS)
        _logo64_photo = ImageTk.PhotoImage(_logo64)
        logo_panel = tk.Label(left, image=_logo64_photo, bg=PANEL)
        logo_panel.image = _logo64_photo
        logo_panel.pack(pady=(12,2))
    except: pass

tk.Label(left, text="MUET JAMSHORO", bg=PANEL, fg=ACCENT,
         font=("Consolas",8,"bold")).pack()
tk.Label(left, text="Forensic Carver v4.0", bg=PANEL, fg=MUTED,
         font=("Consolas",7)).pack(pady=(0,6))

sep()

tk.Label(left,text="DISK IMAGE",bg=PANEL,fg=MUTED,
         font=("Consolas",8)).pack(anchor="w",padx=12,pady=(4,2))
tk.Button(left,text="Load Image",command=browse_file,
          bg=ACCENT,fg="#0b0f19",font=("Consolas",10,"bold"),
          relief=tk.FLAT,pady=6,cursor="hand2").pack(fill=tk.X,padx=12,pady=(0,2))

file_label = tk.Label(left,text="No file selected",bg=PANEL,fg=TEXT,
                      font=("Consolas",8),wraplength=196,justify=tk.LEFT)
file_label.pack(anchor="w",padx=12)
size_label = tk.Label(left,text="",bg=PANEL,fg=MUTED,font=("Consolas",7))
size_label.pack(anchor="w",padx=12)
md5_label  = tk.Label(left,text="",bg=PANEL,fg=MUTED,font=("Consolas",7),wraplength=196)
md5_label.pack(anchor="w",padx=12,pady=(0,4))

sep()
tk.Label(left,text="TARGET TYPES",bg=PANEL,fg=MUTED,
         font=("Consolas",8)).pack(anchor="w",padx=12,pady=(4,4))

for ft in file_signatures:
    var=tk.BooleanVar(value=True); type_vars[ft]=var
    col=TYPE_COLOR.get(ft,TEXT)
    tk.Checkbutton(left,text=f"  {ft.upper()}",variable=var,
                   bg=PANEL,fg=col,selectcolor=PANEL2,
                   activebackground=PANEL,activeforeground=col,
                   font=("Consolas",9),anchor="w").pack(fill=tk.X,padx=16)

sep()

start_btn = tk.Button(left,text="▶  START RECOVERY",command=start_recovery,
                      bg=GREEN,fg="#0b0f19",font=("Consolas",10,"bold"),
                      relief=tk.FLAT,pady=8,cursor="hand2")
start_btn.pack(fill=tk.X,padx=12,pady=2)

for txt,cmd,col in [
    ("Clear Logs",      clear_logs,          YELLOW),
    ("Open Output",     open_output_folder,  ACCENT),
]:
    tk.Button(left,text=txt,command=cmd,bg=PANEL2,fg=col,
              font=("Consolas",9),relief=tk.FLAT,pady=4,
              cursor="hand2").pack(fill=tk.X,padx=12,pady=2)

sep()
tk.Label(left,text="ANALYSIS",bg=PANEL,fg=MUTED,
         font=("Consolas",8)).pack(anchor="w",padx=12,pady=(4,2))

for txt,cmd,col in [
    ("Byte Frequency",  show_byte_freq,  TEAL),
    ("Extract Strings", extract_strings, "#ec4899"),
    ("Compare Files",   compare_files,   ORANGE),
]:
    tk.Button(left,text=txt,command=cmd,bg=PANEL2,fg=col,
              font=("Consolas",9),relief=tk.FLAT,pady=4,
              cursor="hand2").pack(fill=tk.X,padx=12,pady=2)

sep()
tk.Label(left,text="EXPORT",bg=PANEL,fg=MUTED,
         font=("Consolas",8)).pack(anchor="w",padx=12,pady=(4,2))

for txt,cmd,col in [
    ("HTML Report",  export_html_report, PURPLE),
    ("CSV",          export_csv,         ORANGE),
    ("JSON",         export_json,        TEAL),
]:
    tk.Button(left,text=txt,command=cmd,bg=PANEL2,fg=col,
              font=("Consolas",9),relief=tk.FLAT,pady=4,
              cursor="hand2").pack(fill=tk.X,padx=12,pady=2)

# ── CENTER NOTEBOOK ──────────────────────────
center = tk.Frame(main, bg=BG)
center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

nb = ttk.Notebook(center)
nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

# Tab 1 — Scan Log
lf = tk.Frame(nb, bg=BG); nb.add(lf, text=" SCAN LOG ")
log_box = tk.Text(lf,bg=PANEL2,fg=TEXT,font=("Consolas",9),
                  insertbackground=ACCENT,relief=tk.FLAT,padx=8,pady=6,wrap=tk.NONE)
ls=tk.Scrollbar(lf,bg=PANEL2,troughcolor=PANEL2,command=log_box.yview)
log_box.config(yscrollcommand=ls.set)
ls.pack(side=tk.RIGHT,fill=tk.Y); log_box.pack(fill=tk.BOTH,expand=True)

# Tab 2 — Hex Dump
hf=tk.Frame(nb,bg=BG); nb.add(hf,text=" HEX DUMP ")
hex_box=tk.Text(hf,bg=PANEL2,fg="#7dd3fc",font=("Consolas",9),
                relief=tk.FLAT,padx=8,pady=6,wrap=tk.NONE,state=tk.DISABLED)
hs=tk.Scrollbar(hf,bg=PANEL2,troughcolor=PANEL2,command=hex_box.yview)
hex_box.config(yscrollcommand=hs.set)
hs.pack(side=tk.RIGHT,fill=tk.Y); hex_box.pack(fill=tk.BOTH,expand=True)

# Tab 3 — Metadata
mf=tk.Frame(nb,bg=BG); nb.add(mf,text=" METADATA ")
meta_box=tk.Text(mf,bg=PANEL2,fg=TEXT,font=("Consolas",10),
                 relief=tk.FLAT,padx=12,pady=10,wrap=tk.WORD,state=tk.DISABLED)
for tag,col in [(ACCENT,ACCENT),(TEXT,TEXT),(RED,RED),(YELLOW,YELLOW),
                (GREEN,GREEN),(MUTED,MUTED),(ORANGE,ORANGE),(TEAL,TEAL)]:
    meta_box.tag_config(tag,foreground=col)
meta_box.pack(fill=tk.BOTH,expand=True)

# Progress
progress=ttk.Progressbar(center,style="TProgressbar")
progress.pack(fill=tk.X,padx=4,pady=(0,4))

# ── RIGHT PANEL ──────────────────────────────
right=tk.Frame(main,bg=PANEL,width=320)
right.pack(side=tk.RIGHT,fill=tk.Y)
right.pack_propagate(False)

sf=tk.Frame(right,bg=PANEL); sf.pack(fill=tk.X,padx=8,pady=(10,2))
search_var=tk.StringVar(); search_var.trace("w",filter_list)
tk.Entry(sf,textvariable=search_var,bg=PANEL2,fg=TEXT,
         insertbackground=ACCENT,font=("Consolas",9),
         relief=tk.FLAT).pack(side=tk.LEFT,fill=tk.X,expand=True,padx=(0,4))

filter_var=tk.StringVar(value="ALL"); filter_var.trace("w",filter_list)
combo=ttk.Combobox(sf,textvariable=filter_var,width=6,
                   values=["ALL","JPG","PNG","PDF","GIF","BMP","ZIP","MP3","DOCX","RAR"],
                   state="readonly",font=("Consolas",9))
combo.pack(side=tk.LEFT)

file_list=tk.Listbox(right,bg=PANEL2,fg=TEXT,font=("Consolas",9),
                     selectbackground=ACCENT,selectforeground="#0b0f19",
                     relief=tk.FLAT,activestyle="none")
fl_sb=tk.Scrollbar(right,bg=PANEL2,troughcolor=PANEL2,command=file_list.yview)
file_list.config(yscrollcommand=fl_sb.set)
fl_sb.pack(side=tk.RIGHT,fill=tk.Y,padx=(0,2))
file_list.pack(fill=tk.X,padx=(6,0),pady=(0,2))
file_list.bind("<<ListboxSelect>>",show_preview)

tk.Button(right,text="✕  Delete Selected",command=delete_selected,
          bg=PANEL2,fg=RED,font=("Consolas",8),
          relief=tk.FLAT,pady=3,cursor="hand2").pack(fill=tk.X,padx=6,pady=2)

tk.Frame(right,bg="#1e293b",height=1).pack(fill=tk.X,padx=8,pady=4)
tk.Label(right,text="IMAGE PREVIEW",bg=PANEL,fg=MUTED,
         font=("Consolas",8)).pack(anchor="w",padx=8)

image_label=tk.Label(right,bg=PANEL2,fg=MUTED,font=("Consolas",9),
                     relief=tk.FLAT,width=38,height=12)
image_label.pack(fill=tk.X,padx=6,pady=(2,6))

# ── Startup banner ────────────────────────────
log("╔══════════════════════════════════════════════╗", ACCENT)
log("║  MUET JAMSHORO — FORENSIC FILE CARVER v4.0  ║", ACCENT)
log("║  Mehran Univ. of Engineering & Technology   ║", MUTED)
log("╚══════════════════════════════════════════════╝", ACCENT)
log("  Types    : JPG PNG PDF GIF BMP ZIP MP3 DOCX RAR", MUTED)
log("  NEW v4.0 :", YELLOW)
log("    ✔ MUET logo in window icon + sidebar",     GREEN)
log("    ✔ SHA256 hash (in addition to MD5+SHA1)",  GREEN)
log("    ✔ Magic byte identifier for every file",   GREEN)
log("    ✔ Live scan timer",                        GREEN)
log("    ✔ Image MD5 computed on load",             GREEN)
log("    ✔ Byte frequency bar chart",               GREEN)
log("    ✔ ASCII string extractor",                 GREEN)
log("    ✔ Side-by-side file comparator",           GREEN)
log("    ✔ JSON export (in addition to HTML+CSV)",  GREEN)
log("    ✔ DOCX + RAR signature support",           GREEN)
log("\n  Load a disk image and click START RECOVERY\n", TEXT)

root.mainloop()
