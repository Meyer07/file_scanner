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




            


