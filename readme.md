# Malware Scanner

A defensive, **read-only** command-line scanner for files and directories that
combines two detection strategies:

1. **Hash-based detection** — computes MD5/SHA1/SHA256 for each file and
   checks them against a local database of known-malicious hashes
   (`signatures/malware_hashes.txt`), with an optional live lookup against
   [VirusTotal](https://www.virustotal.com/) if you supply an API key.
2. **Heuristic / static analysis** — inspects file content and structure
   without executing anything:
   - Shannon entropy (flags packed/encrypted/compressed content)
   - Suspicious string/pattern matching (encoded PowerShell, process-injection
     API names, registry persistence keys, obfuscation patterns, etc.)
   - File-extension vs. magic-byte mismatch and double-extension disguises
     (e.g. `invoice.pdf.exe`)
   - Windows PE structural analysis via `pefile` (suspicious imports, missing
     import table, RWX sections, abnormal section entropy)
   - Office (OOXML) embedded VBA macro detection

Findings are weighted by severity into a score, which maps to a risk level:
`CLEAN`, `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`, or `MALICIOUS` (an exact hash
match against the known-bad DB or a positive VirusTotal hit always forces
`MALICIOUS`/high severity, regardless of score).

**This tool never executes, unpacks-and-runs, or modifies the files it
scans.** All analysis is passive, read-only inspection of bytes and file
structure — safe to run against untrusted files.

## Install

```bash
pip install -r requirements.txt
```

(`pefile` is only used for `.exe`/`.dll` structural analysis; everything
else works with the Python standard library.)

## Usage

```bash
# Scan a single file
python scanner.py suspicious_file.exe

# Scan a directory recursively
python scanner.py ./Downloads --recursive

# Also write a full machine-readable report
python scanner.py ./Downloads -r --json report.json

# Include VirusTotal hash lookups (requires a free API key)
python scanner.py suspicious_file.exe --vt-api-key YOUR_API_KEY

# Use your own hash database instead of the bundled one
python scanner.py ./Downloads -r --db /path/to/hashes.txt
```

Exit code is `1` if any file is classified `MALICIOUS` or `HIGH RISK`
(handy for CI pipelines / pre-upload checks), `0` otherwise.

## Growing the hash database

`signatures/malware_hashes.txt` ships with only the industry-standard
[EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) hash, so you
can verify the scanner works out of the box. For real coverage, populate it
with hashes from a threat-intel feed such as
[MalwareBazaar](https://bazaar.abuse.ch/export/) (free SHA256 exports).
Format is one `hash,label` pair per line.

## Project layout

```
malware_scanner/
├── scanner.py       # CLI entry point, orchestration, scoring, reporting
├── hash_checker.py  # hashing + local DB + VirusTotal lookup
├── heuristics.py    # entropy, string, extension, PE, macro checks
├── signatures/
│   └── malware_hashes.txt
├── requirements.txt
└── README.md
```

## Limitations (read before relying on this)

- This is a **heuristic aid**, not a replacement for a real antivirus/EDR
  product. False positives and false negatives are both possible.
- Static analysis only — it does not sandbox or dynamically execute files,
  so behavior-only threats (e.g. malicious logic that only triggers under
  specific runtime conditions) won't be caught.
- The bundled hash DB is a stub; real-world use requires feeding it a proper
  threat-intel source.
- PE analysis covers common injection/packing indicators, not a full
  disassembly or unpacking pipeline.