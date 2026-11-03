#!/usr/bin/env python3
"""Build-time harvest for the real-text injection fixture (dev tool, never shipped).

Network is used **here only**; the detector itself stays offline. Everything written is public data:

* real CVE descriptions from the CVE.org CNA API,
* real security-related GitHub issue bodies from public repositories,
* tool-result-shaped JSON documents built from public KEV/EPSS/NVD/OSV/GHSA payloads.

``manifest.json`` records the source URL, fetch date, SHA-256 and ``kind`` for every document. Nothing
is retyped by hand: each file is the bytes the source returned, truncated to a bounded size.

Usage: ``python tools/injection_real_harvest.py`` (re-fetches and rewrites the fixture).
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "injection_real")
MANIFEST = os.path.join(FIXTURE, "manifest.json")

UA = "aurascan-injection-fixture/1.0 (+local spike harness)"
MAX_DOC_CHARS = 6000

CVE_IDS = (
    "CVE-2023-4863",
    "CVE-2024-3094",
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-38545",
    "CVE-2022-0185",
    "CVE-2023-44487",
    "CVE-2024-6387",
    "CVE-2021-4034",
    "CVE-2022-0847",
    "CVE-2023-22809",
    "CVE-2024-1086",
    "CVE-2022-2588",
    "CVE-2023-32233",
    "CVE-2024-28085",
    "CVE-2023-4911",
    "CVE-2022-47929",
    "CVE-2021-3156",
    "CVE-2023-38408",
    "CVE-2024-2961",
    "CVE-2022-3602",
    "CVE-2023-0286",
    "CVE-2020-1472",
    "CVE-2019-0708",
    "CVE-2017-0144",
)

# repo -> GitHub issue search query. Bodies only; pull requests are filtered out below.
ISSUE_SOURCES = (
    ("curl/curl", "repo:curl/curl security in:body type:issue"),
    ("openssl/openssl", "repo:openssl/openssl CVE in:body type:issue"),
    ("nodejs/node", "repo:nodejs/node security vulnerability in:body type:issue"),
    ("python/cpython", "repo:python/cpython CVE in:body type:issue"),
    ("django/django", "repo:django/django security in:body type:issue"),
    ("golang/go", "repo:golang/go security in:body type:issue"),
    ("kubernetes/kubernetes", "repo:kubernetes/kubernetes CVE in:body type:issue"),
    ("git/git", "repo:git/git security in:body type:issue"),
)

OSV_IDS = ("GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33", "GHSA-3f95-mxq2-2f6p")
GHSA_IDS = ("GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33")
EPSS_CVES = ("CVE-2023-4863", "CVE-2024-3094", "CVE-2021-44228", "CVE-2024-6387")


def get(url, accept="application/json"):
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def get_json(url):
    return json.loads(get(url).decode("utf-8"))


def bounded(payload):
    text = payload.decode("utf-8", "replace")
    if len(text) > MAX_DOC_CHARS:
        text = text[:MAX_DOC_CHARS] + "\n"
    return text


class Writer(object):
    def __init__(self):
        self.entries = []
        self.used = set()

    def write(self, kind, slug, url, text):
        directory = os.path.join(FIXTURE, kind)
        os.makedirs(directory, exist_ok=True)
        name = slug + (".json" if kind == "tool-result" else ".txt")
        path = os.path.join(directory, name)
        if path in self.used:
            return
        self.used.add(path)

        payload = text.encode("utf-8")
        with open(path, "wb") as handle:
            handle.write(payload)
        self.entries.append(
            {
                "kind": kind,
                "path": os.path.relpath(path, ROOT).replace(os.sep, "/"),
                "source_url": url,
                "fetched_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
        print("  %-58s %6d bytes" % (os.path.relpath(path, ROOT), len(payload)))


def harvest_cves(writer):
    print("CVE descriptions")
    for cve_id in CVE_IDS:
        url = "https://cveawg.mitre.org/api/cve/" + cve_id
        try:
            record = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip %s: %s" % (cve_id, error))
            continue

        descriptions = []
        for container in record.get("containers", {}).get("cna", {}).get("descriptions", []) or []:
            if container.get("lang", "").startswith("en") and container.get("value"):
                descriptions.append(container["value"])
        for container in record.get("containers", {}).get("adp", []) or []:
            for item in container.get("descriptions", []) or []:
                if item.get("lang", "").startswith("en") and item.get("value"):
                    descriptions.append(item["value"])
        if not descriptions:
            continue

        writer.write("cve", cve_id, url, descriptions[0].strip() + "\n")
        time.sleep(0.3)


def harvest_issues(writer):
    print("GitHub issue bodies")
    for repo, query in ISSUE_SOURCES:
        url = "https://api.github.com/search/issues?per_page=8&sort=relevance&q=" + urllib.parse.quote(query)
        try:
            payload = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip %s: %s" % (repo, error))
            continue

        taken = 0
        for item in payload.get("items", []) or []:
            if taken >= 4:
                break
            if item.get("pull_request"):
                continue
            body = (item.get("body") or "").strip()
            if len(body) < 200:
                continue
            slug = "%s-%s" % (repo.replace("/", "-"), item.get("number"))
            writer.write("issue", slug, item.get("html_url") or url, bounded(body.encode("utf-8")))
            taken += 1
        time.sleep(2.0)


def harvest_tool_results(writer):
    print("tool-result-shaped JSON")
    for cve_id in EPSS_CVES[:2]:
        url = "https://api.first.org/data/v1/epss?cve=" + cve_id
        try:
            payload = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip epss %s: %s" % (cve_id, error))
            continue
        document = {"tool": "cve-mcp.epss", "arguments": {"cve": cve_id}, "result": payload}
        writer.write("tool-result", "epss-" + cve_id.lower(), url, json.dumps(document, indent=2) + "\n")
        time.sleep(0.4)

    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        kev = get_json(kev_url)
        for record in kev.get("vulnerabilities", [])[:2]:
            document = {"tool": "cve-mcp.kev", "arguments": {"cve": record.get("cveID")}, "result": record}
            writer.write(
                "tool-result",
                "kev-" + str(record.get("cveID")).lower(),
                kev_url,
                json.dumps(document, indent=2) + "\n",
            )
    except (urllib.error.URLError, ValueError) as error:
        print("  skip kev: %s" % error)

    for cve_id in EPSS_CVES[:2]:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
        try:
            payload = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip nvd %s: %s" % (cve_id, error))
            continue
        document = {"tool": "cve-mcp.nvd", "arguments": {"cve": cve_id}, "result": payload}
        writer.write("tool-result", "nvd-" + cve_id.lower(), url, json.dumps(document, indent=2) + "\n")
        time.sleep(6.5)

    for advisory in OSV_IDS:
        url = "https://api.osv.dev/v1/vulns/" + advisory
        try:
            payload = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip osv %s: %s" % (advisory, error))
            continue
        document = {"tool": "cve-mcp.osv", "arguments": {"id": advisory}, "result": payload}
        writer.write("tool-result", "osv-" + advisory.lower(), url, json.dumps(document, indent=2) + "\n")
        time.sleep(0.4)

    for advisory in GHSA_IDS:
        url = "https://api.github.com/advisories/" + advisory
        try:
            payload = get_json(url)
        except (urllib.error.URLError, ValueError) as error:
            print("  skip ghsa %s: %s" % (advisory, error))
            continue
        document = {"tool": "cve-mcp.ghsa", "arguments": {"id": advisory}, "result": payload}
        writer.write("tool-result", "ghsa-" + advisory.lower(), url, json.dumps(document, indent=2) + "\n")
        time.sleep(1.0)


def main():
    if not os.path.isdir(FIXTURE):
        os.makedirs(FIXTURE)
    writer = Writer()

    harvest_cves(writer)
    harvest_issues(writer)
    harvest_tool_results(writer)

    counts = {}
    for entry in writer.entries:
        counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1

    manifest = {
        "version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "harvest_invocation": "python tools/injection_real_harvest.py",
        "max_document_chars": MAX_DOC_CHARS,
        "public_data_only": True,
        "counts": counts,
        "total": len(writer.entries),
        "source_type_mapping": {
            "cve": "documentation",
            "issue": "source",
            "tool-result": "source",
        },
        "documents": sorted(writer.entries, key=lambda entry: entry["path"]),
    }
    with open(MANIFEST, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print("total=%d %s" % (len(writer.entries), counts))
    return 0 if len(writer.entries) >= 50 else 1


if __name__ == "__main__":
    sys.exit(main())
