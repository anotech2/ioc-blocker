import os
import yaml
import pandas as pd
from dotenv import load_dotenv

from ioc_sources.static_feeds import (
    fetch_spamhaus_drop, fetch_spamhaus_edrop,
    fetch_emerging_threats_compromised, fetch_dshield_top
)
from ioc_sources.abuseipdb import fetch_abuseipdb
from ioc_sources.otx import fetch_otx_ipv4
from ioc_sources.base import collect_unique
from vt_enrich import vt_score_ip, is_malicious_by_threshold
from panos_api import PanOS

load_dotenv()

# ---------- ENV: device ----------
PAN_FW_IP      = os.getenv("PAN_FW_IP")
PAN_USERNAME   = os.getenv("PAN_USERNAME")
PAN_PASSWORD   = os.getenv("PAN_PASSWORD")
PAN_VSYS       = os.getenv("PAN_VSYS", "vsys1")
PAN_FW_PORT    = int(os.getenv("PAN_FW_PORT", "443"))
PAN_VERIFY     = os.getenv("PAN_VERIFY", "false").lower() in ("1","true","yes")
PAN_TIMEOUT    = int(os.getenv("PAN_TIMEOUT", "30"))
PAN_TRUST_ENV  = os.getenv("PAN_TRUST_ENV", "false").lower() in ("1","true","yes")

# ---------- ENV: policy objects ----------
PAN_DAG_NAME   = os.getenv("PAN_DAG_NAME", "DAG_Block_Malicious")
PAN_DAG_FILTER = os.getenv("PAN_DAG_FILTER", "malicious")  # boolean expression of tag names
PAN_BLOCK_RULE = os.getenv("PAN_BLOCK_RULE", "Block Inbound IOCs")
PAN_UNTRUST    = os.getenv("PAN_UNTRUST_ZONE", "UNTRUST")
PAN_TRUST      = os.getenv("PAN_TRUST_ZONE", "TRUST")
PAN_DAG_MODE   = os.getenv("PAN_DAG_MODE", "objects").lower().strip()  # "objects" | "user-id"

# Cleanup behavior
PAN_DELETE_STALE = os.getenv("PAN_DELETE_STALE", "false").lower() in ("1","true","yes")

# ---------- ENV: VirusTotal / feeds ----------
VT_API_KEY     = os.getenv("VT_API_KEY", "")
SKIP_VT        = os.getenv("SKIP_VT", "false").lower() in ("1","true","yes")
VT_PROGRESS_EVERY = int(os.getenv("VT_PROGRESS_EVERY", "1000"))  # 0 = silent

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")
OTX_PULSE_IDS     = [x.strip() for x in os.getenv("OTX_PULSE_IDS", "").split(",") if x.strip()]

LOCAL_EXCEL_FILE  = os.getenv("LOCAL_EXCEL_FILE", "Block_IOC.xlsx")
LOCAL_EXCEL_SHEET = os.getenv("LOCAL_EXCEL_SHEET", "Sheet1")
LOCAL_EXCEL_COL   = os.getenv("LOCAL_EXCEL_COL", "IP")

# ---------- ENV: limits / progress ----------
PLAIN_LIMIT = int(os.getenv("PLAIN_LIMIT", "0"))   # cap # of plain IPs before VT (0=no cap)
FINAL_LIMIT = int(os.getenv("FINAL_LIMIT", "0"))   # cap final set pushed (0=no cap)
BATCH_USERID = int(os.getenv("BATCH_USERID", "1000"))
UPSERT_PROGRESS_EVERY = int(os.getenv("UPSERT_PROGRESS_EVERY", "500"))

# ---------- CONFIG: feeds & thresholds ----------
with open("feeds.yaml", "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}

vt_mal_min = int(cfg.get("threshold", {}).get("vt_malicious_min", 5))
vt_sus_min = int(cfg.get("threshold", {}).get("vt_suspicious_min", 0))
prov = cfg.get("providers", {})

# ---------- CONNECT ----------
pan = PanOS(
    PAN_FW_IP, PAN_USERNAME, PAN_PASSWORD, PAN_VSYS,
    port=PAN_FW_PORT, verify=PAN_VERIFY, timeout=PAN_TIMEOUT, trust_env=PAN_TRUST_ENV
)
info = pan.show_system_info()
print(f"[+] Connected to: {info['hostname']} serial={info['serial'] or 'unknown'} version={info['sw']}")

# ---------- PULL FEEDS ----------
feeds_ips = set()

if prov.get("spamhaus_drop", True):
    feeds_ips |= fetch_spamhaus_drop()
if prov.get("spamhaus_edrop", True):
    feeds_ips |= fetch_spamhaus_edrop()
if prov.get("emerging_threats", True):
    feeds_ips |= fetch_emerging_threats_compromised()
if prov.get("dshield_top", True):
    feeds_ips |= fetch_dshield_top()

if prov.get("excel_local", False) and os.path.exists(LOCAL_EXCEL_FILE):
    df = pd.read_excel(LOCAL_EXCEL_FILE, sheet_name=LOCAL_EXCEL_SHEET)
    feeds_ips |= collect_unique(df[LOCAL_EXCEL_COL].dropna().astype(str).tolist())

if isinstance(prov.get("abuseipdb"), dict) and prov["abuseipdb"].get("enabled", False) and ABUSEIPDB_API_KEY:
    abuse_cfg = prov["abuseipdb"]
    feeds_ips |= fetch_abuseipdb(
        ABUSEIPDB_API_KEY,
        confidence_min=int(abuse_cfg.get("confidence_min", 75)),
        days=int(abuse_cfg.get("days", 7)),
        limit=int(abuse_cfg.get("limit", 500)),
    )

if isinstance(prov.get("otx"), dict) and prov["otx"].get("enabled", False) and OTX_API_KEY:
    feeds_ips |= fetch_otx_ipv4(OTX_API_KEY, OTX_PULSE_IDS or None)

print(f"[+] Pulled {len(feeds_ips)} unique IP/CIDRs from feeds")

plain = [x for x in feeds_ips if "/" not in x]
cidrs = {x for x in feeds_ips if "/" in x}
print(f"[i] Plain IPs: {len(plain)}, CIDRs: {len(cidrs)}")

if PLAIN_LIMIT > 0 and len(plain) > PLAIN_LIMIT:
    plain = plain[:PLAIN_LIMIT]
    print(f"[i] PLAIN_LIMIT applied → {len(plain)} plain IPs")

# ---------- VT ENRICH ----------
final_ips = set()

if SKIP_VT or not VT_API_KEY:
    final_ips |= set(plain)
    if not VT_API_KEY:
        print("[i] VT_API_KEY not set → skipping VirusTotal enrichment")
    elif SKIP_VT:
        print("[i] SKIP_VT=true → skipping VirusTotal enrichment")
else:
    for i, ip in enumerate(plain, start=1):
        stats = vt_score_ip(ip, VT_API_KEY)
        if is_malicious_by_threshold(stats, vt_mal_min, vt_sus_min):
            final_ips.add(ip)
        if VT_PROGRESS_EVERY > 0 and (i % VT_PROGRESS_EVERY == 0):
            print(f"  ... VT checked {i} items")

# Keep CIDRs always (we can make this stricter later if you prefer)
final_ips |= cidrs

if FINAL_LIMIT > 0 and len(final_ips) > FINAL_LIMIT:
    final_ips = set(list(final_ips)[:FINAL_LIMIT])

print(f"[+] {len(final_ips)} indicators after VT filtering (plus CIDRs)")

# ---------- ENSURE TAG / DAG / RULE ----------
print("[+] Ensuring Tag 'malicious' exists...")
pan.ensure_tag("malicious", color="color1")

print("[+] Ensuring DAG exists...")
pan.ensure_dag(PAN_DAG_NAME, PAN_DAG_FILTER)

print("[+] Ensuring Block Rule exists referencing the DAG...")
pan.ensure_block_rule(PAN_BLOCK_RULE, PAN_UNTRUST, PAN_TRUST, PAN_DAG_NAME)

# ---------- DELTA WITH EXISTING ----------
# existing = { object_name -> "ip" or "ip/cidr" } for objects carrying tag 'malicious'
existing_map = pan.list_address_objects_by_tag("malicious")
existing_values = set(existing_map.values())

to_add = final_ips - existing_values
to_del = existing_values - final_ips if PAN_DELETE_STALE else set()

print(f"[delta] to_add: {len(to_add)}  to_del: {len(to_del)}  (existing={len(existing_values)})")

# ---------- APPLY DELTA ----------
changed = False

if PAN_DAG_MODE == "user-id":
    # Only IPs (no CIDRs) for User-ID
    ips_only = [x for x in to_add if "/" not in x]
    if ips_only:
        print(f"[+] Registering {len(ips_only)} new IPs via User-ID (tag=malicious) ...")
        for i in range(0, len(ips_only), max(1, BATCH_USERID)):
            batch = ips_only[i:i + BATCH_USERID]
            pan.register_ips(batch, "malicious")
            print(f"  ... registered {i + len(batch)} / {len(ips_only)}")
        changed = True
    # Optionally unregister stale
    if to_del:
        ips_del = [x for x in to_del if "/" not in x]
        if ips_del:
            print(f"[+] Unregistering {len(ips_del)} stale IPs (User-ID) ...")
            for i in range(0, len(ips_del), max(1, BATCH_USERID)):
                batch = ips_del[i:i + BATCH_USERID]
                pan.unregister_ips(batch, "malicious")
                print(f"  ... unregistered {i + len(batch)} / {len(ips_del)}")
            changed = True

else:
    # Address objects mode: add new ones only
    if to_add:
        print(f"[+] Creating {len(to_add)} new address objects (tag=malicious) ...")
        for idx, ip in enumerate(sorted(to_add), start=1):
            pan.upsert_address_object(f"IOC_{ip.replace('/', '_')}", ip, "malicious")
            if UPSERT_PROGRESS_EVERY > 0 and (idx % UPSERT_PROGRESS_EVERY == 0):
                print(f"  ... created {idx} / {len(to_add)}")
        changed = True

    # Optionally delete stale objects
    if to_del:
        print(f"[+] Deleting {len(to_del)} stale address objects ...")
        # Build a reverse map value->name(s) from existing_map
        val_to_names = {}
        for name, val in existing_map.items():
            val_to_names.setdefault(val, []).append(name)
        count = 0
        for val in sorted(to_del):
            for name in val_to_names.get(val, []):
                pan.delete_address_object(name)
                count += 1
                if UPSERT_PROGRESS_EVERY > 0 and (count % UPSERT_PROGRESS_EVERY == 0):
                    print(f"  ... deleted {count} / {len(to_del)} values (may map to multiple names)")
        changed = True

# ---------- COMMIT (only if we changed candidate, and only in objects mode) ----------
if PAN_DAG_MODE == "objects" and changed:
    print("[+] Committing ...")
    pan.commit_and_wait()
else:
    if changed:
        print("[i] No commit required (user-id mode).")
    else:
        print("[i] No changes detected; skipping commit.")

# ---------- VERIFY ----------
print("[verify] Candidate config:")
cand_objs = pan.list_malicious_objects()
print(f"  malicious-tagged address objects (candidate): {len(cand_objs)}")
dag = pan.get_dag(PAN_DAG_NAME)
print(f"  DAG '{PAN_DAG_NAME}' filter: {dag.get('filter') if dag else 'NOT FOUND'}")
print(f"  Rule '{PAN_BLOCK_RULE}' exists (candidate): {pan.rule_exists(PAN_BLOCK_RULE)}")

print("[verify] Running config:")
run_objs = pan.list_malicious_objects_running()
print(f"  malicious-tagged address objects (running): {len(run_objs)}")
print(f"  Rule '{PAN_BLOCK_RULE}' exists (running): {pan.rule_exists_running(PAN_BLOCK_RULE)}")

try:
    members = pan.show_dag_members(PAN_DAG_NAME)
    print(f"[verify] DAG members resolved by device (operational): {len(members)}")
except Exception as e:
    print(f"[verify] DAG members query not supported: {e}")

print("[✓] Done.")
