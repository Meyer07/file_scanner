from __future__ import annotations
import argparse
import os
import json
import sys
from datetime import datetime,timezone
import hash_checker
import heuristics

severity_weight={"low":1,"medium":2,"high":3}
max_scan=100*1024*1024 #100 MB saftey cap 

def classify_rank(score:int,hash_hit:bool)->str:
    if hash_hit:
        return "MALICIOUS"
    if score>=10:
        return "HIGH RISK"
    if score>=5:
        return "SUSPICIOUS"
    if score>=1:
        return "LOW RISK"
    return "CLEAN"

def scan_file(filepath:str,local_db:dict,vt_api_key:str | None)->dict:
    result={
    "path":filepath,
    "size_bytes":None,
    "hashes":None,
    "hash_match":None,
    "virustotal":None,
    "findings":[],
    "score":0,
    "risk":"CLEAN",
    "error":None,
    }

    try:
        size=os.path.getsize(filepath)
        result["size_bytes"]=size
        if size>max_scan:
             result["error"] = (
                f"File exceeds {max_scan // (1024*1024)}MB safety cap "
                "for in-memory scanning; skipped content analysis (hashing still attempted).")
        with open(filepath,"rb") as f:
            data=f.read(max_scan)
    except(OSError,PermissionError) as e:
        result["error"]=f"Could not read file: {e}"
        result["risk"]="ERROR"
        return result
    
    hashes=hash_checker.compute_hashes(data)
    result["hashes"]=hashes
    match=hash_checker.check_local_db(hashes,local_db)
    if match:
        result["hash_match"]=match
    

    if vt_api_key:
        vt=hash_checker.check_virustotal(hashes["sha256"],vt_api_key)
        if vt:
            result["virustotal"]=vt
            if vt["malicious"]>0:
                result["findings"].append({
                    "check": "virustotal",
                    "severity": "high",
                    "detail": f"{vt['malicious']}/{vt['total_engines']} VirusTotal engines flag this as malicious",
                })
    
    if size<=max_scan:
        result["findings"]+=heuristics.run_all_heuristics(filepath,data)
    
    score=sum(severity_weight.get(f["severity"],0)for f in result["findings"])
    result["score"]=score
    result["risk"]=classify_rank(score,bool(result["hash_match"]))
    return result


def collect_files(path:str,recursive:bool)->list[str]:
    if os.path.isfile(path):
        return [path]
    files=[]
    if recursive:
        for root, _dirs,filenames in os.walk(path):
            for fn in filenames:
                filenames.append(os.path.join(root,fn))
    else:
        for entry in sorted(os.listdir(path)):
            full=os.path.join(path,entry)
            if os.path.isfile(full):
                files.append(full)
    
    return files



RISK_ORDER = {"MALICIOUS": 0, "HIGH RISK": 1, "SUSPICIOUS": 2, "LOW RISK": 3, "CLEAN": 4, "ERROR": 5}


def print_report(results:list[dict]):
    print()
    print("="*72)
    print("SCAN REPORT")
    print("="*72)

    results_sorted=sorted(results,key=lambda r:RISK_ORDER.get(r["risk"],9))

    counts={}

    for r in results_sorted:
        counts[r["risk"]] = counts.get(r["risk"], 0) + 1
    
    for r in results_sorted:
        flag = {
            "MALICIOUS": "[!!!]",
            "HIGH RISK": "[ ! ]",
            "SUSPICIOUS": "[ ? ]",
            "LOW RISK": "[ . ]",
            "CLEAN": "[ OK ]",
            "ERROR": "[ERR]",
        }.get(r["risk"], "[ ? ]")

        print(f"\n{flag} {r['path']}  —  {r['risk']} (score {r['score']})")
 
        if r["error"]:
            print(f"error: {r['error']}")
        if r["hashes"]:
            print(f"sha256: {r['hashes']['sha256']}")
        if r["hash_match"]:
            print(f">> MATCHED known-malicious hash DB: {r['hash_match']['label']} "f"({r['hash_match']['algo']})")
        if r["virustotal"]:
            vt = r["virustotal"]
            print(f"VirusTotal: {vt['malicious']} malicious / {vt['total_engines']} engines")

        for finding in r["findings"]:
            print(f"- [{finding['severity'].upper():6}] {finding['check']}: {finding['detail']}")
    
    print("\n" + "-" * 72)
    summary = ", ".join(f"{k}: {v}" for k, v in counts.items())
    print(f" Summary — {len(results)} file(s) scanned. {summary}")
    print("-" * 72 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Defensive, read-only file/directory malware scanner "
                    "combining hash-based and heuristic detection."
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recurse into subdirectories")
    parser.add_argument("--json", metavar="FILE",
                        help="Write full JSON report to FILE")
    parser.add_argument("--vt-api-key", metavar="KEY", default=None,
                        help="VirusTotal API key for online hash lookups (optional)")
    parser.add_argument("--db", metavar="FILE", default=hash_checker.LOCAL_DB_PATH,
                        help="Path to local known-hash database (default: bundled signatures file)")
    args = parser.parse_args()
 
    if not os.path.exists(args.path):
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        sys.exit(1)
 
    local_db = hash_checker.load_local_db(args.db)
    files = collect_files(args.path, args.recursive)
 
    if not files:
        print("No files found to scan.")
        sys.exit(0)
 
    print(f"Scanning {len(files)} file(s)"
          f"{' (recursive)' if args.recursive else ''}"
          f"{' with VirusTotal lookups' if args.vt_api_key else ''}...")
 
    results = [scan_file(fp, local_db, args.vt_api_key) for fp in files]
 
    print_report(results)
 
    if args.json:
        report = {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": args.path,
            "recursive": args.recursive,
            "file_count": len(results),
            "results": results,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Full JSON report written to {args.json}")
 
    # Exit code reflects worst finding — useful for CI/automation
    worst = min((RISK_ORDER.get(r["risk"], 9) for r in results), default=9)
    sys.exit(1 if worst <= 1 else 0)  # non-zero if MALICIOUS or HIGH RISK found
 
 
if __name__ == "__main__":
    main()
        





            


