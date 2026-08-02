import math 
import os 
import re
import zipfile
from collections import Counter

def shannon_entropy(data:bytes)->float:
    if not data:
        return 0.0
    counts=Counter(data)
    length=len(data)
    entropy=0.0
    for count in counts.values():
        p=count/length
        entropy-=p*math.log2(p)
    return entropy 

def entropy_findings(data:bytes)->list[dict]:
    findings=[]
    ent=shannon_entropy(data)
    if ent>=7.5:
        findings.append({
            "check": "entropy",
            "severity": "high",
            "detail": f"Very high entropy ({ent:.2f}/8.0) — likely packed or encrypted content",
        })
    elif ent>=6.8:
        findings.append({
            "check": "entropy",
            "severity": "medium",
            "detail": f"Elevated entropy ({ent:.2f}/8.0) — possibly compressed or obfuscated",
        })
    return findings


SUSPICIOUS_PATTERNS={
     "powershell_encoded": rb"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}",
    "powershell_downloadstring": rb"(?i)downloadstring|downloadfile|invoke-expression|iex\s*\(",
    "process_injection_api": rb"(?i)VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection",
    "shellcode_hint": rb"(?i)shellcode|payload\[",
    "reg_run_key": rb"(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "susp_wmi": rb"(?i)Win32_Process|wmic\.exe|WMI\s+process\s+call\s+create",
    "susp_network": rb"(?i)cmd\.exe\s*/c|net\.webclient|bitsadmin|certutil\s+-decode",
    "obfuscation": rb"(?i)eval\s*\(\s*base64_decode|FromBase64String|char\s*\(\s*\d+\s*\)\s*\+\s*char",
    "anti_debug": rb"(?i)IsDebuggerPresent|CheckRemoteDebuggerPresent",
    "self_delete": rb"(?i)del\s+%0|self.*delete|/c\s+del",
}

def suspicious_string_findings(data:bytes)->list[dict]:
    findings=[]
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern,data):
            findings.append({
                "check": f"string:{name}",
                "severity": "medium",
                "detail": f"Matched suspicious pattern '{name}'",
            })
    return findings

MAGIC_BYTES={
     b"MZ": "exe/dll (PE)",
    b"\x7fELF": "elf",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip/office/jar",
    b"\xd0\xcf\x11\xe0": "ole/legacy office",
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF8": "gif",
}

EXT_EXPECTATIONS={
     ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpg",
    ".jpeg": "jpg",
    ".gif": "gif",
    ".exe": "exe/dll (PE)",
    ".dll": "exe/dll (PE)",
    ".docx": "zip/office/jar",
    ".xlsx": "zip/office/jar",
    ".pptx": "zip/office/jar",
    ".zip": "zip/office/jar",
    ".jar": "zip/office/jar",
    ".doc": "ole/legacy office",
    ".xls": "ole/legacy office",
}

def detect_file_type(data:bytes)->str | None:
    for magic, ftype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return ftype
    return None

def extension_mismatch_findings(filepath:str,data:bytes,)->list[dict]:
    findings=[]
    ext=os.path.splitext(filepath)[1].lower()
    actual_type=detect_file_type(data)
    expected_type=EXT_EXPECTATIONS.get(ext)

    if expected_type and actual_type and actual_type !=expected_type:
        findings.append({
            "check": "extension_mismatch",
            "severity": "high",
            "detail": f"File has extension '{ext}' but content looks like '{actual_type}', "
            f"not the expected '{expected_type}' — classic disguise technique",
        })
    name=os.path.basename(filepath)
    parts=name.split(".")
    if len(parts) >= 3 and parts[-1].lower() in ("exe", "scr", "bat", "cmd", "js", "vbs", "ps1"):
        if parts[-2].lower() in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"):
            findings.append({
                "check": "double_extension",
                "severity": "high",
                "detail": f"Filename '{name}' uses a double extension to disguise an executable",
            })
    return findings

SUSPICIOUS_IMPORTS={
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState", "URLDownloadToFile",
    "InternetOpenUrl", "WinExec", "ShellExecute", "IsDebuggerPresent",
    "CreateToolhelp32Snapshot", "AdjustTokenPrivileges", "CryptEncrypt",
}

def pe_findigns(filepath:str)->list[dict]:
    findings=[]
    try:
        import pefile
    except ImportError:
        return findings
    
    try:
        pe=pefile.PE(filepath,fast_load=True)
    except pefile.PEFormatError:
        return findings
    except Exception:
        return findings
    
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
 
        # Suspicious imports
        hit_imports = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        if name in SUSPICIOUS_IMPORTS:
                            hit_imports.add(name)
        if hit_imports:
            findings.append({
                "check": "pe_suspicious_imports",
                "severity": "medium" if len(hit_imports) < 3 else "high",
                "detail": f"Imports commonly abused for injection/evasion: {', '.join(sorted(hit_imports))}",
            })
 
        # No signature / no imports at all can indicate a stub or packed binary
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or len(pe.DIRECTORY_ENTRY_IMPORT) == 0:
            findings.append({
                "check": "pe_no_imports",
                "severity": "medium",
                "detail": "PE file has no (or unreadable) import table — common in packed/obfuscated binaries",
            })
 
        # Section anomalies: high-entropy or executable+writable sections
        for section in pe.sections:
            sec_name = section.Name.decode(errors="ignore").strip("\x00")
            sec_data = section.get_data()
            sec_entropy = shannon_entropy(sec_data) if sec_data else 0
            characteristics = section.Characteristics
            is_write = bool(characteristics & 0x80000000)
            is_exec = bool(characteristics & 0x20000000)
            if sec_entropy >= 7.5:
                findings.append({
                    "check": "pe_section_entropy",
                    "severity": "high",
                    "detail": f"Section '{sec_name}' has very high entropy ({sec_entropy:.2f}) — likely packed",
                })
            if is_write and is_exec:
                findings.append({
                    "check": "pe_rwx_section",
                    "severity": "high",
                    "detail": f"Section '{sec_name}' is both writable and executable — common in shellcode/injection",
                })
 
        # Timestamp sanity check
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts == 0:
                findings.append({
                    "check": "pe_zero_timestamp",
                    "severity": "low",
                    "detail": "Compile timestamp is zero — sometimes stripped to hinder analysis",
                })
        except Exception:
            pass
    finally:
        pe.close()
 
    return findings

def macro_findings(filepath:str)->list[dict]:
    findings=[]
    if not zipfile.is_zipfile(filepath):
        return findings
    try:
        with zipfile.Zipfile(filepath) as z:
            names=z.namelist()
            if any("vbaProject.bin" in n for n in names):
                findings.append({
                    "check": "office_macro",
                    "severity": "medium",
                    "detail": "Document contains embedded VBA macro project (vbaProject.bin) — "
                              "macros are a common malware delivery mechanism",
                })
    except(zipfile.BadZipFile,OSError):
        pass
    return findings


def run_all_heuristics(filepath:str,data:bytes)->list[dict]:
    findings = []
    findings += entropy_findings(data)
    findings += suspicious_string_findings(data)
    findings += extension_mismatch_findings(filepath, data)
    findings += macro_findings(filepath)
    if data.startswith(b"MZ"):
        findings += pe_findings(filepath)
    return findings



