from __future__ import annotations
import hashlib
import json
import os
import urllib.request
import urllib.error

SIGNATURES_DIR=os.path.join(os.path.dirname(__file__),"signatures")
LOCAL_DB_PATH=os.path.join(SIGNATURES_DIR,"malware_hashes.txt")


def compute_hashes(data:bytes)->dict:
    return {
        "md5":hashlib.md5(data).hexdigest(),
        "sha1":hashlib.sha1(data).hexdigest(),
        "sha256":hashlib.sha256(data).hexdigest()
    }

def load_local_db(path:str=LOCAL_DB_PATH)->dict:
    db={}
    if not os.path.exists(path):
        return db
    with open(path,"r") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            parts=line.split(",",1)
            h=parts[0].strip().lower()
            label=parts[1].strip() if len(parts)>1 else "known-malicious"
            db[h]=label
    return db

def check_local_db(hashes:dict,db:dict)->dict|None:
    for algo,value in hashes.items():
        if value.lower() in db:
            return {"algo":algo,"hash":value,"label":db[value.lower()]}
    return None

def check_virustotal(sha256:str,api_key:str,timeout:int=15)->dict | None:
    url=f"https://www.virustotal.com/api/v3/files/{sha256}"
    req=urllib.request.Request(url,headers={"x-apikey":api_key})
    try:
        with urllib.request.urlopen(req,timeout=timeout)as resp:
            payload=json.loads(resp.read().decode())
    except(urllib.error.URLError,urllib.error.HTTPError,TimeoutError,OSError):
        return None
    except Exception:
        return None
    try:
        stats=payload["data"]["attributes"]["last_analysis_stats"]
        malicious=stats.get("malicious",0)
        suspicious=stats.get("suspicious",0)
        total=sum(stats.values())
        return{
            "malicious":malicious,
            "suspicious":suspicious,
            "total_engines":total,
        }
    except(KeyError,TypeError):
        return None


