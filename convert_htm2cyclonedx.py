#!/usr/bin/env python3
"""
buildlog_to_cdx15.py
Konvertiert eine Keil/ARM .build_log.htm Datei in eine CycloneDX 1.5 BOM (JSON).
Usage:
    python buildlog_to_cdx15.py input.build_log.htm output_sbom.json
Ergebnis: CycloneDX specVersion 1.5, Komponenten mit eigenständigem "version"-Feld und optionalem "purl".
"""

import sys
import json
import re
import uuid
from datetime import datetime, timezone
from dateutil import tz
from bs4 import BeautifulSoup
from urllib.parse import quote_plus

def parse_build_log_html(html_text):
    """
    Extrahiert Paket-Einträge aus dem HTML-Text.
    Liefert Liste von dicts mit keys:
      vendor, url, pack_id, pack_name, pack_version, description, components (list)
    """
    soup = BeautifulSoup(html_text, "lxml")

    # Versuche strukturierte Bereiche zu finden (z.B. <pre>, <div>, <table>) sonst fallback auf reines Text-Parsing
    text = soup.get_text("\n", strip=True)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    entries = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        # Erkenne "Package Vendor:"-Blöcke (häufig in Keil build logs)
        if ln.lower().startswith("package vendor:"):
            vendor = ln.split(":",1)[1].strip()
            entry = {"vendor": vendor, "url": None, "pack_id": None, "pack_name": None, "pack_version": None, "description": None, "components": []}
            i += 1
            while i < len(lines) and not lines[i].lower().startswith("package vendor:"):
                cur = lines[i]
                # URL
                if cur.startswith("http://") or cur.startswith("https://"):
                    entry["url"] = cur
                    # versuche pack-id aus URL zu extrahieren
                    m_url = re.search(r"/pack/([A-Za-z0-9_.\-]+?)(?:\.pack)?(?:$|/)", cur)
                    if m_url:
                        entry["pack_id"] = m_url.group(1)
                # Pack identifier Zeile (z.B. ARM.CMSIS.6.2.0 oder ARM.CMSIS-Compiler.2.1.0)
                m_pack = re.match(r"^([A-Za-z0-9_.\-]+(?:\.[0-9][A-Za-z0-9_.\-]*)*)\s*$", cur)
                if m_pack:
                    token = m_pack.group(1)
                    # Heuristik: letzte Komponente numerisch -> Version
                    parts = token.split(".")
                    if len(parts) >= 2 and re.match(r"^\d+(\.\d+)*$", parts[-1]):
                        entry["pack_version"] = parts[-1]
                        entry["pack_name"] = ".".join(parts[:-1])
                        entry["pack_id"] = token
                    else:
                        # fallback: setze pack_name falls noch leer
                        if not entry["pack_name"]:
                            entry["pack_name"] = token
                # Beschreibung (kurze Zeilen, die nicht URL/Component sind)
                if entry["description"] is None and len(cur.split())>2 and "component" not in cur.lower() and "package vendor" not in cur.lower() and "http" not in cur:
                    # einfache Heuristik: wenn Zeile Klammern oder 'CMSIS' enthält, ist es wahrscheinlich Beschreibung
                    if "(" in cur or "CMSIS" in cur or "Cortex" in cur or len(cur) < 120:
                        entry["description"] = cur
                # Komponenten: Zeilen mit '*' oder 'Component:' oder 'Version:'
                if cur.startswith("*") or cur.lower().startswith("component:") or "version:" in cur.lower():
                    comp_line = re.sub(r"^[\*\-\s]+", "", cur)
                    # Muster: Name Version: x.y.z oder Name Version x.y.z
                    m = re.search(r"(?P<name>[\w\s\-\(\)\/\.]+?)\s*(?:Version:|version:|Version|ver:)?\s*(?P<ver>\d+(\.\d+){0,})\b", comp_line)
                    if m:
                        name = m.group("name").strip().rstrip(":")
                        ver = m.group("ver").strip()
                        entry["components"].append({"name": name, "version": ver})
                    else:
                        entry["components"].append({"name": comp_line, "version": "NOASSERTION"})
                i += 1
            entries.append(entry)
            continue
        i += 1

    # Fallback: wenn keine "Package Vendor" Blöcke gefunden wurden, suche nach keil pack URLs oder pack ids im Text
    if not entries:
        packs = []
        for ln in lines:
            if "keil.com/pack" in ln.lower() or re.search(r"\b[A-Za-z0-9_.\-]+?\.\d+\.\d+\.pack\b", ln):
                packs.append(ln)
        for p in packs:
            entry = {"vendor": "ARM", "url": p, "pack_id": None, "pack_name": None, "pack_version": None, "description": None, "components": []}
            m = re.search(r"/pack/([A-Za-z0-9_.\-]+?)(?:\.pack)?(?:$|/)", p)
            if m:
                idpart = m.group(1)
                entry["pack_id"] = idpart
                parts = idpart.split(".")
                if len(parts)>=2 and re.match(r"^\d+(\.\d+)*$", parts[-1]):
                    entry["pack_version"] = parts[-1]
                    entry["pack_name"] = ".".join(parts[:-1])
                else:
                    entry["pack_name"] = idpart
            entries.append(entry)

    return entries

def make_purl_from_pack(entry):
    """
    Versucht, eine einfache purl (Package URL) zu erzeugen, wenn möglich.
    Für Keil packs gibt es kein standardisiertes purl namespace; wir erzeugen eine informative purl:
      pkg:keil/<pack_id>@<version>
    Falls keine pack_id vorhanden, geben wir None zurück.
    """
    pid = entry.get("pack_id") or entry.get("pack_name")
    ver = entry.get("pack_version")
    if not pid:
        return None
    # einfache purl-safe Kodierung
    pid_enc = quote_plus(pid)
    if ver and ver != "NOASSERTION":
        return f"pkg:keil/{pid_enc}@{ver}"
    return f"pkg:keil/{pid_enc}"

def build_cyclonedx_json15(components, project_name="project-dependencies"):
    now = datetime.now(timezone.utc).astimezone(tz.tzutc()).replace(microsecond=0).isoformat()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "tools": [
                {"vendor": "Generated", "name": "buildlog_to_cdx15", "version": "1.0"}
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": "1.0.0",
                "description": "SBOM generated from build_log.htm (CycloneDX 1.5)"
            }
        },
        "components": []
    }

    for c in components:
        # Name fallback: pack_name or pack_id or url
        name = c.get("pack_name") or c.get("pack_id") or (c.get("url") and c["url"].split("/")[-1]) or "unknown"
        version = c.get("pack_version") or "NOASSERTION"
        comp = {
            "type": "library",
            "name": name,
            "version": version,   # eigenständiges Feld wie gewünscht
            "publisher": c.get("vendor") or "NOASSERTION",
            "description": c.get("description") or None,
            "licenses": [{"license": {"id": "NOASSERTION"}}],
        }
        # purl falls möglich
        purl = make_purl_from_pack(c)
        if purl:
            comp["purl"] = purl
        # externe Referenzen (Distribution URL)
        if c.get("url"):
            comp["externalReferences"] = [{"type": "distribution", "url": c["url"]}]
        # Komponenten-Details als property (falls vorhanden)
        if c.get("components"):
            # join als "Name Version; Name2 Version2" oder als strukturierte Liste
            # comp["properties"] = [{"name": "components", "value": "; ".join([f\"{x.get('name')} {x.get('version')}\" for x in c['components']])}]
            comp["properties"] = [{"name": "components", "value": "; ".join([f"{x.get('name')} {x.get('version')}" for x in c['components']])}]
        # Entferne None-Felder
        if comp.get("description") is None:
            del comp["description"]
        bom["components"].append(comp)

    return bom

def main():
    if len(sys.argv) < 3:
        print("Usage: python buildlog_to_cdx15.py input.build_log.htm output_sbom.json")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    parsed = parse_build_log_html(html)
    if not parsed:
        print("Warnung: Keine Paket-Einträge gefunden. Prüfe das Format der build_log.htm.")
    bom = build_cyclonedx_json15(parsed, project_name="project-dependencies")

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(bom, out, indent=2, ensure_ascii=False)

    print(f"SBOM geschrieben nach {output_file} mit {len(bom['components'])} Komponenten.")

if __name__ == "__main__":
    main()
