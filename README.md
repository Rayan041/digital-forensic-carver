# digital-forensic-carver
A powerful Python-based forensic toolkit for carving, analyzing, and investigating files from raw disk images — packed with hashing, entropy insights, and a clean GUI.
Semester project
Digital Forensic File Carver v4.0 is a comprehensive Python-based forensic application designed to recover, analyze, and examine files from raw disk images. Built with a user-friendly graphical interface using Tkinter, the tool enables investigators, students, and cybersecurity enthusiasts to perform file carving without requiring advanced command-line knowledge.

The tool operates using signature-based file carving techniques, identifying known file headers and footers to extract recoverable data from disk images such as .img, .dd, .bin, .raw, and other formats. It supports recovery of multiple file types including images (JPG, PNG, GIF, BMP), documents (PDF, DOCX), archives (ZIP, RAR), and audio files (MP3).

Beyond simple recovery, the tool integrates advanced forensic analysis features. It generates cryptographic hashes (MD5, SHA1, SHA256) for integrity verification, calculates entropy to help detect compressed or encrypted data, and performs magic byte analysis to identify actual file types. A built-in hex dump viewer allows low-level inspection of file contents, while additional utilities such as string extraction and byte frequency analysis provide deeper insight into recovered data.

The application also includes file comparison functionality based on hash values, enabling investigators to determine file similarity or duplication. For reporting purposes, the tool can export detailed forensic reports in multiple formats including HTML, CSV, and JSON, making it suitable for documentation and evidence presentation.

Recovered files are organized automatically, and the interface provides real-time logging, progress tracking, file previews (for supported formats), and metadata visualization. The inclusion of entropy labeling and confidence levels further assists users in assessing the reliability and nature of recovered files.

Developed as an academic and practical project at Mehran University of Engineering & Technology (MUET), this tool serves as both a learning platform and a functional utility for digital forensic investigations. It demonstrates key concepts in data recovery, file system analysis, and cybersecurity while maintaining simplicity and usability through its graphical interface.

This tool is intended strictly for educational and ethical forensic use.
