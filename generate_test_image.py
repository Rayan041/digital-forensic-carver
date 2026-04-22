"""
generate_test_image.py
Run this script once — it creates  test_disk.dd
which you can then load into your Forensic File Carver.
"""

import os
import struct
import zlib

output_file = "test_disk.dd"

# ──────────────────────────────────────────────
# 1.  MINIMAL VALID JPEG  (grey 8×8 pixels)
# ──────────────────────────────────────────────
def make_jpeg():
    # Tiny but spec-valid 8×8 grey JPEG
    data = bytes([
        0xFF,0xD8,0xFF,0xE0, 0x00,0x10,                    # SOI + APP0 marker
        0x4A,0x46,0x49,0x46,0x00,                           # "JFIF\0"
        0x01,0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,       # version, aspect
        0xFF,0xDB,0x00,0x43,0x00,                            # DQT marker
    ] + [8]*64 +                                             # quantisation table
    [
        0xFF,0xC0,0x00,0x0B,0x08,                           # SOF0 marker
        0x00,0x08,0x00,0x08,                                 # 8×8
        0x01,0x01,0x11,0x00,                                 # 1 component
        0xFF,0xC4,0x00,0x1F,0x00,                           # DHT marker
        0x00,0x01,0x05,0x01,0x01,0x01,0x01,0x01,
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,  # SOS
        0x7F,0xA4,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,            # compressed data
        0xFF,0xD9                                             # EOI
    ])
    return data

# ──────────────────────────────────────────────
# 2.  MINIMAL VALID PNG  (1×1 red pixel)
# ──────────────────────────────────────────────
def make_png():
    def chunk(name, data):
        c = name + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig    = b'\x89PNG\r\n\x1a\n'
    ihdr   = chunk(b'IHDR', struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    raw    = b'\x00\xFF\x00\x00'          # filter=0, R=255, G=0, B=0  → red pixel
    idat   = chunk(b'IDAT', zlib.compress(raw))
    iend   = chunk(b'IEND', b'')
    return sig + ihdr + idat + iend

# ──────────────────────────────────────────────
# 3.  MINIMAL VALID PDF  (one page, "Hello Forensics")
# ──────────────────────────────────────────────
def make_pdf():
    stream = b"BT /F1 16 Tf 50 750 Td (Hello Forensics - Test PDF) Tj ET"
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream +
        b"\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000266 00000 n \n"
        b"0000000370 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n441\n"
        b"%%EOF\n"
    )
    return pdf

# ──────────────────────────────────────────────
# 4.  BUILD THE DISK IMAGE
# ──────────────────────────────────────────────
def build_image():
    jpeg = make_jpeg()
    png  = make_png()
    pdf  = make_pdf()

    # Junk padding between files (simulates real disk slack space)
    junk_small  = b'\x00' * 512
    junk_medium = b'\xAA\xBB\xCC\xDD' * 256     # 1 KB of patterned bytes
    junk_large  = b'\x00' * 2048

    image = (
        b"FORENSIC_TEST_IMAGE\x00"   # disk label / preamble
        + junk_large
        + jpeg
        + junk_medium
        + png
        + junk_small
        + pdf
        + junk_large
        + b"END_OF_IMAGE\x00"
    )

    with open(output_file, "wb") as f:
        f.write(image)

    size_kb = len(image) / 1024
    print(f"[✔] Created: {output_file}")
    print(f"    Size   : {size_kb:.1f} KB  ({len(image)} bytes)")
    print(f"    Embedded:")
    print(f"      JPEG  — {len(jpeg)} bytes")
    print(f"      PNG   — {len(png)} bytes")
    print(f"      PDF   — {len(pdf)} bytes")
    print()
    print(f"Load '{output_file}' into the Forensic File Carver and click Start Recovery.")

if __name__ == "__main__":
    build_image()
