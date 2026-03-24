"""
cve_crawler.py — Multi-source CVE intelligence crawler
Sources: NVD, CIRCL, EPSS, GitHub PoC-in-GitHub DB,
         ExploitDB, PacketStorm, Vulhub, Shodan CVE DB,
         OSV (Open Source Vulnerabilities), GitHub Advisory DB,
         Vulners, AttackerKB, CISA KEV catalog
"""

import httpx
import asyncio
import json
import time
import re
from datetime import datetime, timedelta
from pathlib import Path

CACHE_FILE = Path("cve_cache.json")
CACHE_TTL  = 3600  # 1 hour

# ── API endpoints ─────────────────────────────────────────────────
NVD_API       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API     = "https://cve.circl.lu/api/cve"
EPSS_API      = "https://api.first.org/data/v1/epss"
GITHUB_REPO   = "https://api.github.com/search/repositories"
GITHUB_CODE   = "https://api.github.com/search/code"
OSV_API       = "https://api.osv.dev/v1/vulns"
OSV_QUERY     = "https://api.osv.dev/v1/query"
GHSA_API      = "https://api.github.com/advisories"
VULNERS_API   = "https://vulners.com/api/v3/search/lucene/"
SHODAN_CVE    = "https://cvedb.shodan.io/cve"
CISA_KEV      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACKERKB    = "https://api.attackerkb.com/v1/topics"


# ── Cache helpers ─────────────────────────────────────────────────

def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            return {}
    return {}

def _save_cache(data: dict):
    try:
        CACHE_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass

def _cache_get(key: str):
    cache = _load_cache()
    entry = cache.get(key)
    if entry and time.time() - entry.get("ts", 0) < CACHE_TTL:
        return entry.get("data")
    return None

def _cache_set(key: str, data):
    cache = _load_cache()
    cache[key] = {"ts": time.time(), "data": data}
    _save_cache(cache)


# ── Core CVE data ─────────────────────────────────────────────────

async def fetch_nvd(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(NVD_API, params={"cveId": cve_id})
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities", [])
                if vulns:
                    cve     = vulns[0].get("cve", {})
                    descs   = cve.get("descriptions", [])
                    desc    = next((d["value"] for d in descs if d["lang"] == "en"), "")
                    metrics = cve.get("metrics", {})
                    cvss    = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                    score, severity, vector = None, "UNKNOWN", ""
                    if cvss:
                        cd       = cvss[0].get("cvssData", {})
                        score    = cd.get("baseScore")
                        severity = cd.get("baseSeverity", "UNKNOWN")
                        vector   = cd.get("vectorString", "")
                    # Also get CVSS v2 if v3 missing
                    if score is None:
                        cvss2 = metrics.get("cvssMetricV2", [])
                        if cvss2:
                            score    = cvss2[0].get("cvssData", {}).get("baseScore")
                            severity = _score_to_severity(score)
                    return {
                        "description": desc,
                        "score":       score,
                        "severity":    severity,
                        "vector":      vector,
                        "references":  [ref["url"] for ref in cve.get("references", [])[:10]],
                        "weaknesses":  [d["value"] for w in cve.get("weaknesses", [])
                                        for d in w.get("description", [])],
                        "published":   cve.get("published", "")[:10],
                        "modified":    cve.get("lastModified", "")[:10],
                        "source":      "nvd"
                    }
    except Exception:
        pass
    return {}


async def fetch_circl(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{CIRCL_API}/{cve_id}")
            if r.status_code == 200:
                d = r.json()
                return {
                    "description": d.get("summary", ""),
                    "score":       d.get("cvss"),
                    "severity":    _score_to_severity(d.get("cvss")),
                    "references":  d.get("references", [])[:10],
                    "weaknesses":  d.get("cwe", []),
                    "published":   d.get("Published", "")[:10],
                    "modified":    d.get("Modified", "")[:10],
                    "source":      "circl"
                }
    except Exception:
        pass
    return {}


async def fetch_epss(cve_id: str) -> dict:
    """Exploit Prediction Scoring System — probability of real-world exploitation."""
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(EPSS_API, params={"cve": cve_id})
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    return {
                        "epss_score":      round(float(data[0].get("epss", 0)) * 100, 2),
                        "epss_percentile": round(float(data[0].get("percentile", 0)) * 100, 1),
                    }
    except Exception:
        pass
    return {}


# ── OSV — Open Source Vulnerabilities ─────────────────────────────

async def fetch_osv(cve_id: str) -> dict:
    """Fetch from OSV database — covers npm, PyPI, Go, Maven, RubyGems etc."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(OSV_QUERY,
                json={"query": {"aliases": [cve_id]}},
                headers={"Content-Type": "application/json"})
            if r.status_code == 200:
                vulns = r.json().get("vulns", [])
                if vulns:
                    v = vulns[0]
                    affected = []
                    for pkg in v.get("affected", []):
                        p = pkg.get("package", {})
                        name = p.get("name", "")
                        eco  = p.get("ecosystem", "")
                        ranges = pkg.get("ranges", [])
                        versions = []
                        for rng in ranges:
                            for ev in rng.get("events", []):
                                if "fixed" in ev:
                                    versions.append(f"fixed: {ev['fixed']}")
                                elif "introduced" in ev and ev["introduced"] != "0":
                                    versions.append(f"from: {ev['introduced']}")
                        affected.append({
                            "package":   f"{eco}/{name}",
                            "versions":  versions[:3]
                        })
                    return {
                        "osv_id":       v.get("id", ""),
                        "osv_summary":  v.get("summary", ""),
                        "osv_affected": affected[:5],
                        "osv_severity": v.get("database_specific", {}).get("severity", ""),
                    }
    except Exception:
        pass
    return {}


# ── GitHub Advisory Database ──────────────────────────────────────

async def fetch_ghsa(cve_id: str) -> list[dict]:
    """Search GitHub Security Advisory Database."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(GHSA_API,
                params={"cve_id": cve_id, "per_page": 5},
                headers={"Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28"})
            if r.status_code == 200:
                for adv in r.json():
                    results.append({
                        "ghsa_id":     adv.get("ghsa_id", ""),
                        "summary":     adv.get("summary", ""),
                        "severity":    adv.get("severity", ""),
                        "url":         adv.get("html_url", ""),
                        "published":   adv.get("published_at", "")[:10],
                        "ecosystem":   adv.get("vulnerabilities", [{}])[0].get("package", {}).get("ecosystem", "") if adv.get("vulnerabilities") else "",
                        "package":     adv.get("vulnerabilities", [{}])[0].get("package", {}).get("name", "") if adv.get("vulnerabilities") else "",
                        "patched":     adv.get("vulnerabilities", [{}])[0].get("patched_versions", "") if adv.get("vulnerabilities") else "",
                    })
    except Exception:
        pass
    return results


# ── Vulners ───────────────────────────────────────────────────────

async def fetch_vulners(cve_id: str) -> list[dict]:
    """Search Vulners database for bulletins, patches, exploits."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(VULNERS_API,
                json={"query": cve_id, "size": 10, "fields": ["id","title","type","cvss","published","href"]},
                headers={"Content-Type": "application/json"})
            if r.status_code == 200:
                data = r.json().get("data", {}).get("search", [])
                for item in data:
                    src = item.get("_source", {})
                    results.append({
                        "id":        src.get("id", ""),
                        "title":     src.get("title", ""),
                        "type":      src.get("type", ""),
                        "score":     src.get("cvss", {}).get("score") if src.get("cvss") else None,
                        "published": src.get("published", "")[:10],
                        "url":       src.get("href", ""),
                    })
    except Exception:
        pass
    return results


# ── CISA KEV catalog ──────────────────────────────────────────────

async def check_cisa_kev(cve_id: str) -> dict:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(CISA_KEV)
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities", [])
                for v in vulns:
                    if v.get("cveID", "").upper() == cve_id.upper():
                        return {
                            "kev":               True,
                            "kev_vendor":        v.get("vendorProject", ""),
                            "kev_product":       v.get("product", ""),
                            "kev_action":        v.get("requiredAction", ""),
                            "kev_due_date":      v.get("dueDate", ""),
                            "kev_ransomware":    v.get("knownRansomwareCampaignUse", "") == "Known",
                            "kev_notes":         v.get("notes", ""),
                        }
    except Exception:
        pass
    return {"kev": False}


# ── Shodan CVE DB ─────────────────────────────────────────────────

async def fetch_shodan_cve(cve_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{SHODAN_CVE}/{cve_id}")
            if r.status_code == 200:
                d = r.json()
                return {
                    "exposed_hosts": d.get("count", 0),
                    "ransomware":    d.get("ransomware_campaign", False),
                }
    except Exception:
        pass
    return {}


# ── GitHub PoC search ─────────────────────────────────────────────

async def search_github(cve_id: str) -> list[dict]:
    results = []
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    # 1. PoC-in-GitHub curated database
    try:
        year = re.search(r'CVE-(\d{4})-', cve_id)
        if year:
            async with httpx.AsyncClient(timeout=12, headers=headers) as c:
                url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year.group(1)}/{cve_id}.json"
                r   = await c.get(url)
                if r.status_code == 200:
                    for entry in r.json():
                        results.append({
                            "type":        "poc_db",
                            "name":        entry.get("full_name", ""),
                            "url":         entry.get("html_url", ""),
                            "description": (entry.get("description") or "")[:120],
                            "stars":       entry.get("stargazers_count", 0),
                            "updated":     entry.get("pushed_at", "")[:10],
                            "language":    entry.get("language", ""),
                        })
    except Exception:
        pass

    # 2. General GitHub repo search
    try:
        async with httpx.AsyncClient(timeout=15, headers=headers) as c:
            r = await c.get(GITHUB_REPO, params={
                "q": f"{cve_id} exploit poc",
                "sort": "stars", "order": "desc", "per_page": 8
            })
            if r.status_code == 200:
                for repo in r.json().get("items", []):
                    if not any(x["name"] == repo.get("full_name") for x in results):
                        results.append({
                            "type":        "repo",
                            "name":        repo.get("full_name", ""),
                            "url":         repo.get("html_url", ""),
                            "description": (repo.get("description") or "")[:120],
                            "stars":       repo.get("stargazers_count", 0),
                            "language":    repo.get("language", ""),
                            "updated":     repo.get("updated_at", "")[:10],
                            "topics":      repo.get("topics", []),
                        })
    except Exception:
        pass

    # 3. Code file search
    try:
        async with httpx.AsyncClient(timeout=15, headers=headers) as c:
            r = await c.get(GITHUB_CODE, params={
                "q": f"{cve_id} in:file,readme", "per_page": 5
            })
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    results.append({
                        "type":     "code_file",
                        "name":     item.get("name", ""),
                        "url":      item.get("html_url", ""),
                        "repo":     item.get("repository", {}).get("full_name", ""),
                        "path":     item.get("path", ""),
                        "language": item.get("repository", {}).get("language", ""),
                    })
    except Exception:
        pass

    results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    return results


# ── ExploitDB ─────────────────────────────────────────────────────

async def search_exploitdb(cve_id: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
            r = await c.get("https://www.exploit-db.com/search",
                params={"cve": cve_id.replace("CVE-", ""),
                        "draw": 1, "start": 0, "length": 15},
                headers={"X-Requested-With": "XMLHttpRequest",
                         "Accept": "application/json",
                         "User-Agent": "Mozilla/5.0 (security research)"})
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    eid = item.get("id", "")
                    results.append({
                        "id":       eid,
                        "title":    item.get("description", ""),
                        "url":      f"https://www.exploit-db.com/exploits/{eid}",
                        "type":     item.get("type", {}).get("name", ""),
                        "platform": item.get("platform", {}).get("name", ""),
                        "date":     item.get("date_published", ""),
                        "author":   item.get("author", {}).get("name", ""),
                        "verified": item.get("verified", False),
                    })
    except Exception:
        pass
    return results


# ── PacketStorm ───────────────────────────────────────────────────

async def search_packetstorm(cve_id: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
            r = await c.get("https://packetstormsecurity.com/search/",
                params={"q": cve_id},
                headers={"User-Agent": "Mozilla/5.0 (security research)"})
            if r.status_code == 200:
                matches = re.findall(
                    r'href="(/files/\d+/[^"]+)"[^>]*>\s*([^<]{4,80})<', r.text)
                for path, title in matches[:10]:
                    results.append({
                        "title": title.strip(),
                        "url":   f"https://packetstormsecurity.com{path}",
                    })
    except Exception:
        pass
    return results


# ── Vulhub Docker labs ────────────────────────────────────────────

async def search_vulhub(cve_id: str) -> list[dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(GITHUB_REPO, params={
                "q": f"{cve_id} org:vulhub", "per_page": 5},
                headers={"Accept": "application/vnd.github+json"})
            if r.status_code == 200:
                for repo in r.json().get("items", []):
                    results.append({
                        "name":        repo.get("full_name", ""),
                        "url":         repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:120],
                        "type":        "docker_lab",
                    })
    except Exception:
        pass
    return results


# ── Main fetch — all sources in parallel ─────────────────────────

async def fetch_cve(cve_id: str) -> dict:
    cve_id = cve_id.upper().strip()
    cached = _cache_get(f"cve_full:{cve_id}")
    if cached:
        return cached

    result = {"id": cve_id}

    # Core data: NVD → CIRCL fallback
    nvd = await fetch_nvd(cve_id)
    if nvd:
        result.update(nvd)
    else:
        circl = await fetch_circl(cve_id)
        if circl:
            result.update(circl)

    if not result.get("description"):
        result["description"] = "Could not fetch CVE data. Verify the CVE ID."

    # All enrichment sources in parallel
    (epss, osv, ghsa, vulners_res, kev, shodan,
     github, exploitdb, packetstorm, vulhub) = await asyncio.gather(
        fetch_epss(cve_id),
        fetch_osv(cve_id),
        fetch_ghsa(cve_id),
        fetch_vulners(cve_id),
        check_cisa_kev(cve_id),
        fetch_shodan_cve(cve_id),
        search_github(cve_id),
        search_exploitdb(cve_id),
        search_packetstorm(cve_id),
        search_vulhub(cve_id),
        return_exceptions=True
    )

    # Merge safe results
    for src in [epss, osv, kev, shodan]:
        if isinstance(src, dict):
            result.update(src)

    result["ghsa"]    = ghsa    if isinstance(ghsa, list)    else []
    result["vulners"] = vulners_res if isinstance(vulners_res, list) else []

    result["pocs"] = {
        "github":       github      if isinstance(github, list)      else [],
        "exploit_db":   exploitdb   if isinstance(exploitdb, list)   else [],
        "packet_storm": packetstorm if isinstance(packetstorm, list) else [],
        "vulhub":       vulhub      if isinstance(vulhub, list)      else [],
    }
    result["poc_count"] = sum(len(v) for v in result["pocs"].values())

    _cache_set(f"cve_full:{cve_id}", result)
    return result


# ── NVD keyword / recent search ───────────────────────────────────

async def search_recent_cves(keyword: str = "", limit: int = 10) -> list[dict]:
    # NVD API 2.0 requires keywordSearch to be >= 3 chars
    if keyword and len(keyword.strip()) < 3:
        return []

    cache_key = f"search:{keyword}:{limit}"
    cached    = _cache_get(cache_key)
    if cached:
        return cached

    results = []
    params  = {"resultsPerPage": limit, "startIndex": 0}
    
    if keyword:
        params["keywordSearch"] = keyword.strip()
    else:
        # Default to last 7 days for "Recent" feed
        end   = datetime.utcnow()
        start = end - timedelta(days=7)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"]   = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.get(NVD_API, params=params)
            if r.status_code == 200:
                data = r.json()
                for vuln in data.get("vulnerabilities", []):
                    cve   = vuln.get("cve", {})
                    descs = cve.get("descriptions", [])
                    desc  = next((d["value"] for d in descs if d["lang"] == "en"), "")
                    
                    m     = cve.get("metrics", {})
                    cvss  = m.get("cvssMetricV31", m.get("cvssMetricV30", []))
                    score, sev = None, "UNKNOWN"
                    if cvss:
                        cd = cvss[0].get("cvssData", {})
                        score = cd.get("baseScore")
                        sev   = cd.get("baseSeverity", "UNKNOWN")
                    
                    results.append({
                        "id":          cve.get("id", ""),
                        "description": desc[:200] + ("..." if len(desc) > 200 else ""),
                        "score":       score,
                        "severity":    sev,
                        "published":   cve.get("published", "")[:10],
                    })
            elif r.status_code == 403:
                # NVD Rate Limit or Forbidden
                return [{"error": "NVD API Rate Limit Exceeded. Try again in 30s."}]
    except Exception as e:
        return [{"error": f"Connection Error: {str(e)}"}]

    if results:
        _cache_set(cache_key, results)
    return results


# ── Helpers ───────────────────────────────────────────────────────

def _score_to_severity(score) -> str:
    if score is None: return "UNKNOWN"
    s = float(score)
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    return "LOW"

def extract_cve_ids(text: str) -> list[str]:
    return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))
