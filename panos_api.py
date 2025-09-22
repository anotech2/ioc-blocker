import requests
import time
import xml.etree.ElementTree as ET
from urllib.parse import quote
from typing import List, Dict, Optional, Tuple

# Lab convenience; in prod, add your CA and set verify=True
requests.packages.urllib3.disable_warnings()


class PanOS:
    """
    PAN-OS XML API helper with:
      - custom port / verify / timeout / proxy bypass
      - commit-and-wait
      - ensure TAG, DAG, RULE, address objects
      - User-ID registration
      - candidate & running verification
      - zone discovery + safe fallback for rules
      - idempotent helpers (list-by-tag, delete)
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        vsys: str = "vsys1",
        port: int = 443,
        verify: bool = False,
        timeout: int = 30,
        trust_env: bool = False,  # False => ignore system/corp proxies
    ):
        self.host = host
        self.username = username
        self.password = password
        self.vsys = vsys
        self.port = int(port)
        self.timeout = int(timeout)
        self.s = requests.Session()
        self.s.verify = verify
        self.s.trust_env = trust_env
        self.key = self._keygen()

    # ---------- low-level ----------
    def _api_url(self) -> str:
        return f"https://{self.host}:{self.port}/api/"

    def _keygen(self) -> str:
        url = f"{self._api_url()}?type=keygen&user={quote(self.username)}&password={quote(self.password)}"
        r = self.s.get(url, timeout=self.timeout)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        key = root.findtext(".//key")
        if not key:
            msg = root.findtext(".//msg/line") or r.text[:200]
            raise RuntimeError(f"Failed to get PAN-OS API key: {msg}")
        return key

    def _get(self, params: dict) -> ET.Element:
        p = dict(params)
        p["key"] = self.key
        r = self.s.get(self._api_url(), params=p, timeout=self.timeout)
        r.raise_for_status()
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as e:
            raise RuntimeError(f"Invalid XML response: {e}\nBody: {r.text[:500]}")
        status = root.get("status", "success")
        if status != "success":
            msg = root.findtext(".//msg/line") or r.text[:200]
            raise RuntimeError(f"PAN-OS API error: {msg}")
        return root

    # wrappers
    def _config_get(self, xpath: str) -> ET.Element:
        return self._get({"type": "config", "action": "get", "xpath": xpath})

    def _config_edit(self, xpath: str, element_xml: str) -> ET.Element:
        return self._get({"type": "config", "action": "edit", "xpath": xpath, "element": element_xml})

    def _config_set(self, xpath: str, element_xml: str) -> ET.Element:
        return self._get({"type": "config", "action": "set", "xpath": xpath, "element": element_xml})

    def _config_delete(self, xpath: str) -> ET.Element:
        return self._get({"type": "config", "action": "delete", "xpath": xpath})

    # ---------- system ----------
    def show_system_info(self) -> Dict[str, str]:
        r = self._get({"type": "op", "cmd": "<show><system><info></info></system></show>"})
        return {
            "hostname": r.findtext(".//hostname") or "",
            "serial": r.findtext(".//serial") or "",
            "sw": r.findtext(".//sw-version") or "",
        }

    # ---------- commit ----------
    def commit_and_wait(self, desc: str = "IOC auto-commit") -> None:
        root = self._get({"type": "commit", "cmd": f"<commit><description>{desc}</description></commit>"})
        jobid = root.findtext(".//job")
        if not jobid:
            raise RuntimeError("Commit did not return a job id")
        print(f"[+] Commit job started (id={jobid})")
        while True:
            time.sleep(2)
            jobs = self._get({"type": "op", "cmd": "<show><jobs><all></all></jobs></show>"})
            found = False
            for j in jobs.findall(".//job"):
                if j.findtext("id") == jobid:
                    found = True
                    status = (j.findtext("status") or "").upper()
                    result = (j.findtext("result") or "").upper()
                    pct = j.findtext("progress") or "?"
                    print(f"    job {jobid}: {status} {pct}%")
                    if status == "FIN":
                        print(f"[+] Commit job {jobid} finished: {result}")
                        if result != "OK":
                            msg = j.findtext("details/line") or j.findtext("details")
                            raise RuntimeError(f"Commit failed: {result} {msg or ''}")
                        return
            if not found:
                print(f"    job {jobid}: polling (not listed yet)")

    # ---------- running config snapshot ----------
    def _running_root(self) -> ET.Element:
        return self._get({"type": "op", "cmd": "<show><config><running></running></config></show>"})

    # ---------- zones ----------
    def list_zones(self) -> List[str]:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/zone"
        try:
            root = self._config_get(xpath)
        except Exception:
            return []
        names = []
        for e in root.findall(".//entry"):
            nm = e.get("name") or e.attrib.get("name")
            if nm:
                names.append(nm)
        return names

    def _resolve_zones(self, from_zone: str, to_zone: str) -> Tuple[str, str]:
        zones = set(self.list_zones())
        if not zones:
            print("[!] No zones returned from config; using 'any' for from/to.")
            return "any", "any"
        fz = from_zone if from_zone in zones or from_zone == "any" else None
        tz = to_zone if to_zone in zones or to_zone == "any" else None
        if fz is None:
            print(f"[!] Requested from-zone '{from_zone}' not found. Available: {sorted(zones)}. Using 'any'.")
            fz = "any"
        if tz is None:
            print(f"[!] Requested to-zone '{to_zone}' not found. Available: {sorted(zones)}. Using 'any'.")
            tz = "any"
        return fz, tz

    # ---------- TAGS ----------
    def ensure_tag(self, tag_name: str, color: str = "color1") -> None:
        """
        Ensure a tag exists in this vsys. Address objects cannot reference a non-existent tag.
        """
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/tag"
        xpath = f"{base}/entry[@name='{tag_name}']"
        element = f"<entry name='{tag_name}'><color>{color}</color></entry>"
        try:
            self._config_edit(xpath, element)
        except Exception:
            self._config_set(base, element)

    # ---------- objects / groups / rules ----------
    def ensure_dag(self, group_name: str, tag_filter: str = "malicious") -> None:
        """
        PAN-OS DAG filter is a boolean expression of tag names, e.g.:
          "malicious" or "malicious AND highrisk" — NOT 'tag eq malicious'.
        """
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address-group"
        xpath = f"{base}/entry[@name='{group_name}']"
        element = f"<entry name='{group_name}'><dynamic><filter>{tag_filter}</filter></dynamic></entry>"
        try:
            self._config_edit(xpath, element)
        except Exception:
            self._config_set(base, element)

    def upsert_address_object(self, name: str, ip_or_cidr: str, tag: str = "malicious") -> None:
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address"
        xpath = f"{base}/entry[@name='{name}']"
        element = (
            f"<entry name='{name}'>"
            f"<ip-netmask>{ip_or_cidr}</ip-netmask>"
            f"<tag><member>{tag}</member></tag>"
            f"</entry>"
        )
        try:
            self._config_edit(xpath, element)
        except Exception:
            self._config_set(base, element)

    def delete_address_object(self, name: str) -> None:
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address"
        xpath = f"{base}/entry[@name='{name}']"
        self._config_delete(xpath)

    def ensure_block_rule(self, rule_name: str, from_zone: str, to_zone: str, dag_name: str) -> None:
        fz, tz = self._resolve_zones(from_zone, to_zone)
        parent = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/rulebase/security/rules"
        xpath = f"{parent}/entry[@name='{rule_name}']"

        def zone_xml(tag: str, value: str) -> str:
            if value == "any":
                return f"<{tag}><member>any</member></{tag}>"
            return f"<{tag}><member>{value}</member></{tag}>"

        element = (
            f"<entry name='{rule_name}'>"
            f"{zone_xml('from', fz)}"
            f"{zone_xml('to', tz)}"
            f"<source><member>{dag_name}</member></source>"
            f"<destination><member>any</member></destination>"
            f"<source-user><member>any</member></source-user>"
            f"<category><member>any</member></category>"
            f"<application><member>any</member></application>"
            f"<service><member>any</member></service>"
            f"<action>deny</action>"
            f"<description>Auto-block malicious IPs.</description>"
            f"</entry>"
        )
        try:
            self._config_edit(xpath, element)
        except Exception:
            self._config_set(parent, element)

    # ---------- verification (candidate) ----------
    def list_address_objects(self) -> List[Dict[str, str]]:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address"
        try:
            root = self._config_get(xpath)
        except Exception:
            return []
        out = []
        for e in root.findall(".//entry"):
            name = e.get("name") or e.attrib.get("name")
            ipnm = e.findtext("./ip-netmask") or ""
            tags = [m.text for m in e.findall("./tag/member")]
            out.append({"name": name, "ip": ipnm, "tags": ",".join(tags)})
        return out

    def list_address_objects_by_tag(self, tag: str) -> Dict[str, str]:
        """
        Returns {object_name: ip_or_cidr} for address objects in this vsys carrying 'tag'.
        """
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address"
        try:
            root = self._config_get(xpath)
        except Exception:
            return {}
        out: Dict[str, str] = {}
        for e in root.findall(".//entry"):
            name = e.get("name") or e.attrib.get("name")
            ipnm = e.findtext("./ip-netmask") or ""
            tags = {m.text for m in e.findall("./tag/member")}
            if tag in tags and name and ipnm:
                out[name] = ipnm
        return out

    def list_malicious_objects(self) -> List[Dict[str, str]]:
        return [o for o in self.list_address_objects() if "malicious" in (o.get("tags") or "")]

    def get_dag(self, group_name: str) -> Optional[Dict[str, str]]:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address-group/entry[@name='{group_name}']"
        try:
            root = self._config_get(xpath)
        except Exception:
            return None
        e = root.find(".//entry")
        if e is None:
            return None
        filt = e.findtext("./dynamic/filter") or ""
        return {"name": group_name, "filter": filt}

    def rule_exists(self, rule_name: str) -> bool:
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/rulebase/security/rules/entry[@name='{rule_name}']"
        try:
            root = self._config_get(xpath)
        except Exception:
            return False
        return root.find(".//entry") is not None

    # ---------- verification (running) ----------
    def list_malicious_objects_running(self) -> List[Dict[str, str]]:
        root = self._running_root()
        out = []
        for e in root.findall(f".//config/devices/entry/vsys/entry[@name='{self.vsys}']/address/entry"):
            name = e.get("name") or e.attrib.get("name")
            ipnm = e.findtext("./ip-netmask") or ""
            tags = [m.text for m in e.findall("./tag/member")]
            if "malicious" in tags:
                out.append({"name": name, "ip": ipnm})
        return out

    def rule_exists_running(self, rule_name: str) -> bool:
        root = self._running_root()
        e = root.find(f".//config/devices/entry/vsys/entry[@name='{self.vsys}']/rulebase/security/rules/entry[@name='{rule_name}']")
        return e is not None

    def show_dag_members(self, group_name: str) -> List[str]:
        r = self._get({
            "type": "op",
            "cmd": f"<show><object><dynamic-address-group><name>{group_name}</name></dynamic-address-group></object></show>"
        })
        members = []
        for m in r.findall(".//members/*"):
            txt = (m.text or "").strip()
            if txt:
                members.append(txt)
        return members

    # ---------- User-ID IP→tag registration ----------
    def register_ips(self, ips: List[str], tag: str = "malicious") -> None:
        if not ips:
            return
        entries = "".join(
            [f"<entry ip='{ip}'><tag><member>{tag}</member></tag></entry>" for ip in ips]
        )
        cmd = (
            "<uid-message><version>2.0</version><type>update</type>"
            f"<payload><register>{entries}</register></payload></uid-message>"
        )
        self._get({"type": "user-id", "cmd": cmd})

    def unregister_ips(self, ips: List[str], tag: str = "malicious") -> None:
        if not ips:
            return
        entries = "".join(
            [f"<entry ip='{ip}'><tag><member>{tag}</member></tag></entry>" for ip in ips]
        )
        cmd = (
            "<uid-message><version>2.0</version><type>update</type>"
            f"<payload><unregister>{entries}</unregister></payload></uid-message>"
        )
        self._get({"type": "user-id", "cmd": cmd})
