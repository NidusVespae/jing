#!/usr/bin/env python3
"""
镜 (Jing / Mirror) — persona-linkage self-audit.  Stdlib only.

Tries to de-anonymize YOU, never anyone else: collects public evidence from
your own assets (domains, GitHub accounts) and reports every link that
crosses a separation you declared between your identities.

Sources (all free, keyless):
  github  — public repos of registered accounts: profile fields, commit
            author/committer names + emails, commit timezone offsets
  rdap    — registration data for registered domains (redaction check)
  dns     — NS / MX / TXT / SOA via DNS-over-HTTPS (shared Cloudflare NS pair,
            shared verification tokens, SOA contact)
  ct      — crt.sh certificate transparency (SANs naming two clusters)
  page    — homepage + security.txt: analytics/beacon IDs, emails, author
            meta, HTML comments, private-identifier strings

Scope: every domain and GitHub account in the config must appear verbatim in
your asset list (--registry), or the run aborts SCOPE UNCONFIRMED.

Usage:
  mirror.py --config mirror.json --registry assets.md --out linkage.md
  mirror.py --config ... --json            # machine-readable to stdout

Exit codes: 0 no cross-separation links, 1 links found, 2 any reading failed
or scope unconfirmed (a failed reading is never an all-clear).
"""
import argparse
import datetime as dt
import html
import json
import re
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "jing-mirror/1.3 (self-audit of owner's own assets)"
TIMEOUT = 20
MAX_COMMITS_PER_REPO = 300
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------- transport
def fetch(url, accept="application/json", timeout=None):
    """Return (status, body_text). Raises nothing; status 0 = transport error."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:  # DNS failure, timeout, TLS
        return 0, "%s: %s" % (type(e).__name__, e)


def fetch_json(url, timeout=None):
    st, body = fetch(url, timeout=timeout)
    if st != 200:
        return st, None, body[:200]
    try:
        return st, json.loads(body), ""
    except ValueError as e:
        return st, None, "bad JSON: %s" % e


# ---------------------------------------------------------------- model
class Audit:
    def __init__(self, cfg):
        self.cfg = cfg
        self.readings = []   # (source, target, ok, detail)
        self.evidence = []   # dicts: persona_a, persona_b, kind, field, source, value, conf
        # private identifiers: list of {"label":..., "value":...}; never echoed
        self.private = [p for p in cfg.get("private_identifiers", []) if p.get("value")]
        self.cluster_of = {}
        for cname, members in cfg["clusters"].items():
            for m in members:
                self.cluster_of[m] = cname

    def reading(self, source, target, ok, detail=""):
        # error pages arrive as raw HTML; keep the status line, not the page
        detail = re.sub(r"<[^>]+>", " ", str(detail))
        detail = re.sub(r"\s+", " ", detail).strip()[:160]
        self.readings.append((source, target, ok, detail))

    def link(self, a, b, kind, field, source, value, conf):
        self.evidence.append(dict(a=a, b=b, kind=kind, field=field,
                                  source=source, value=value, conf=conf))

    def scan_private(self, text, persona, field, source):
        """Flag any private identifier appearing in public text of `persona`."""
        low = (text or "").lower()
        for p in self.private:
            if p["value"].lower() in low:
                # value deliberately masked in the report
                self.link(persona, p.get("persona", "jonathan"), "private-identifier",
                          field, source, "matched private identifier: %s" % p["label"],
                          "high")

    # severity: crossing a declared separation
    def classify(self, e):
        ca, cb = self.cluster_of.get(e["a"]), self.cluster_of.get(e["b"])
        if e["a"] == e["b"] or (ca and ca == cb):
            return "INFO"  # same persona or same cluster — deliberate
        if not ca or not cb:
            return "MEDIUM"  # persona not mapped — needs operator call
        return {"high": "CRITICAL", "medium": "HIGH", "low": "MEDIUM"}[e["conf"]]


# ---------------------------------------------------------------- scope
def check_scope(cfg, registry_path):
    try:
        with open(registry_path, encoding="utf-8") as f:
            reg = f.read()
    except OSError as e:
        return ["registry unreadable: %s" % e]
    missing = []
    for d in cfg.get("domains", {}):
        if d not in reg:
            missing.append("domain %s" % d)
    for acct in cfg.get("github_accounts", {}):
        if acct not in reg:
            missing.append("github account %s" % acct)
    return missing


# ---------------------------------------------------------------- github
NOREPLY = re.compile(r"@users\.noreply\.github\.com$", re.I)


def audit_github(a):
    for acct, persona in a.cfg.get("github_accounts", {}).items():
        st, prof, err = fetch_json("https://api.github.com/users/%s" % acct)
        if prof is None:
            a.reading("github", acct, False, "profile HTTP %s %s" % (st, err))
            continue
        for fld in ("name", "company", "blog", "location", "email", "bio", "twitter_username"):
            v = prof.get(fld)
            if v:
                a.scan_private(str(v), persona, "profile.%s" % fld, "github:%s" % acct)
                a.cross_handle(str(v), persona, "profile.%s" % fld, "github:%s" % acct)
        repos, page = [], 1
        while True:
            st, data, err = fetch_json(
                "https://api.github.com/users/%s/repos?type=owner&per_page=100&page=%d" % (acct, page))
            if data is None:
                a.reading("github", acct, False, "repo list HTTP %s %s" % (st, err))
                break
            repos += [r for r in data if not r.get("fork")]
            if len(data) < 100:
                break
            page += 1
        a.reading("github", acct, True, "%d public repos" % len(repos))
        offsets = {}
        for r in repos:
            name = r["full_name"]
            n, page, seen_emails = 0, 1, {}
            while n < MAX_COMMITS_PER_REPO:
                st, commits, err = fetch_json(
                    "https://api.github.com/repos/%s/commits?per_page=100&page=%d" % (name, page))
                if commits is None:
                    if st == 409:  # empty repo
                        break
                    a.reading("github", name, False, "commits HTTP %s %s" % (st, err))
                    break
                for c in commits:
                    n += 1
                    cm = c.get("commit", {})
                    for role in ("author", "committer"):
                        who = cm.get(role) or {}
                        em, nm = who.get("email", ""), who.get("name", "")
                        key = (em.lower(), nm)
                        if key not in seen_emails:
                            seen_emails[key] = c.get("sha", "")[:8]
                        date = who.get("date", "")
                        m = re.search(r"([+-]\d\d:\d\d)$", date)
                        if m and m.group(1) != "+00:00":
                            offsets[m.group(1)] = offsets.get(m.group(1), 0) + 1
                if len(commits) < 100:
                    break
                page += 1
                time.sleep(0.5)
            a.reading("github", name, True, "%d commits read" % n)
            for (em, nm), sha in seen_emails.items():
                src = "github:%s@%s" % (name, sha)
                if em and not NOREPLY.search(em) and "noreply@github.com" not in em \
                        and not a.is_private_val(em):
                    # a real, non-noreply address that isn't on the private list:
                    # unmapped, so the operator must decide whose it is
                    a.link(persona, "unknown-email", "commit-email", "non-noreply commit email",
                           src, a.mask(em), "medium")
                a.scan_private(nm, persona, "commit author name", src)
                a.scan_private(em, persona, "commit email", src)
        if offsets:
            top = sorted(offsets.items(), key=lambda kv: -kv[1])
            a.link(persona, persona, "timezone", "commit UTC offsets",
                   "github:%s" % acct, ", ".join("%s×%d" % kv for kv in top[:3]), "low")


# ---------------------------------------------------------------- rdap
def audit_rdap(a):
    for dom, persona in a.cfg.get("domains", {}).items():
        st, data, err = fetch_json("https://rdap.org/domain/%s" % dom)
        if data is None and shutil.which("whois"):
            try:
                w = subprocess.run(["whois", dom], capture_output=True, text=True,
                                   timeout=40).stdout
            except Exception as e:
                w = ""
                err = "whois %s" % e
            if w.strip():
                a.reading("rdap", dom, True, "via whois (no RDAP for this TLD)")
                a.scan_private(w, persona, "WHOIS record", "whois:%s" % dom)
                reg = "\n".join(l for l in w.splitlines() if l.lower().startswith("registrant"))
                if reg and not re.search(r"redacted|privacy|proxy|withheld|data protected|not disclosed",
                                         reg, re.I):
                    a.link(persona, "registrant", "whois-registrant",
                           "registrant fields (unredacted)", "whois:%s" % dom,
                           "registrant fields present — review", "medium")
                continue
        if data is None:
            a.reading("rdap", dom, False, "HTTP %s %s" % (st, err))
            continue
        a.reading("rdap", dom, True, "")
        blob = json.dumps(data)
        a.scan_private(blob, persona, "RDAP record", "rdap:%s" % dom)
        for ent in data.get("entities", []):
            roles = ",".join(ent.get("roles", []))
            if "registrant" not in roles:
                continue
            vc = json.dumps(ent.get("vcardArray", ""))
            if not re.search(r"redacted|privacy|proxy|withheld|data protected", vc, re.I) and \
                    re.search(r'"fn",\s*\{\},\s*"text",\s*"[^"]{2,}"', vc):
                a.link(persona, "registrant", "rdap-registrant", "registrant vCard (unredacted)",
                       "rdap:%s" % dom, "registrant fields present — review", "medium")


# ---------------------------------------------------------------- dns
def doh(name, rtype):
    dig = shutil.which("dig")
    if dig:
        try:
            out = subprocess.run([dig, "+short", "+time=5", "+tries=2", rtype, name]
                                 + ([os.environ["MIRROR_DNS"]] if os.environ.get("MIRROR_DNS") else []),
                                 capture_output=True, text=True, timeout=30)
            if out.returncode == 0:
                return [l.strip() for l in out.stdout.splitlines() if l.strip()
                        and not l.startswith(";")], ""
            err = "dig rc=%s %s" % (out.returncode, out.stderr.strip()[:120])
        except Exception as e:
            err = "dig %s" % e
    st, data, err = fetch_json("https://dns.google/resolve?name=%s&type=%s"
                               % (urllib.parse.quote(name), rtype))
    if data is None or data.get("Status") not in (0, 3):
        return None, "HTTP %s %s" % (st, err)
    return [ans.get("data", "") for ans in data.get("Answer", [])
            if ans.get("type") == {"NS": 2, "MX": 15, "TXT": 16, "SOA": 6}[rtype]], ""


def audit_dns(a):
    ns_by, txt_by = {}, {}
    for dom, persona in a.cfg.get("domains", {}).items():
        ok = True
        for rt in ("NS", "MX", "TXT", "SOA"):
            vals, err = doh(dom, rt)
            if vals is None:
                a.reading("dns", "%s %s" % (dom, rt), False, err)
                ok = False
                continue
            if rt == "NS":
                ns_by[dom] = frozenset(v.rstrip(".").lower() for v in vals)
            elif rt == "TXT":
                txt_by[dom] = [v.strip('"') for v in vals]
                for v in txt_by[dom]:
                    a.scan_private(v, persona, "TXT record", "dns:%s" % dom)
            elif rt == "SOA":
                for v in vals:
                    a.scan_private(v, persona, "SOA rname", "dns:%s" % dom)
            elif rt == "MX":
                for v in vals:
                    a.scan_private(v, persona, "MX", "dns:%s" % dom)
        if ok and not ns_by.get(dom):
            # every registered domain is delegated; an empty NS answer means the
            # resolver could not see, not that there is nothing to see
            a.reading("dns", "%s NS" % dom, False, "empty NS answer — resolver blind, not clean")
            ns_by.pop(dom, None)
        elif ok:
            a.reading("dns", dom, True, "NS=%s" % ",".join(sorted(ns_by.get(dom, []))))
    doms = list(ns_by)
    for i in range(len(doms)):
        for j in range(i + 1, len(doms)):
            d1, d2 = doms[i], doms[j]
            if ns_by[d1] and ns_by[d1] == ns_by[d2]:
                conf = "high" if all(n.endswith("ns.cloudflare.com") for n in ns_by[d1]) else "medium"
                a.link(a.cfg["domains"][d1], a.cfg["domains"][d2], "shared-ns-pair",
                       "identical nameserver set", "dns:%s,%s" % (d1, d2),
                       ", ".join(sorted(ns_by[d1])), conf)
    # verification tokens / SPF includes repeated across domains
    tok = re.compile(r"(google-site-verification=\S+|MS=\S+|[a-z0-9-]+-verification=\S+|include:\S+)", re.I)
    seen = {}
    for dom, vals in txt_by.items():
        for v in vals:
            for t in tok.findall(v):
                if t.lower().startswith("include:_spf.") or t.lower() in (
                        "include:_spf.google.com", "include:spf.protection.outlook.com"):
                    continue  # generic provider includes are not identifying
                seen.setdefault(t, set()).add(dom)
    for t, ds in seen.items():
        if len(ds) > 1:
            ds = sorted(ds)
            a.link(a.cfg["domains"][ds[0]], a.cfg["domains"][ds[1]], "shared-txt-token",
                   "TXT token in both zones", "dns:%s" % ",".join(ds), t[:60], "high")


# ---------------------------------------------------------------- ct
def audit_ct(a):
    doms = a.cfg.get("domains", {})
    for dom, persona in doms.items():
        url = "https://crt.sh/?q=%s&output=json&exclude=expired" % urllib.parse.quote(dom)
        st, data, err = fetch_json(url, timeout=90)
        if data is None:
            time.sleep(5)
            st, data, err = fetch_json(url, timeout=90)
        if data is None:
            a.reading("ct", dom, False, "HTTP %s %s" % (st, err))
            continue
        a.reading("ct", dom, True, "%d cert entries" % len(data))
        for c in data:
            sans = set(c.get("name_value", "").lower().split("\n"))
            for other, op in doms.items():
                if other == dom:
                    continue
                if any(s == other or s.endswith("." + other) for s in sans):
                    a.link(persona, op, "shared-cert", "SAN on same certificate",
                           "crt.sh id %s" % c.get("id"), "%s + %s" % (dom, other), "high")
                    break


# ---------------------------------------------------------------- page
FP = {
    "ga4": re.compile(r"\bG-[A-Z0-9]{6,12}\b"),
    "ua": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "gtm": re.compile(r"\bGTM-[A-Z0-9]{4,9}\b"),
    "cf-beacon": re.compile(r'data-cf-beacon=[\'"]\{[^}]*"token":\s*"([0-9a-f]{32})"', re.I),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "author": re.compile(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)', re.I),
    "comment": re.compile(r"<!--(.{8,200}?)-->", re.S),
}


def audit_pages(a):
    fps = {}
    for dom, persona in a.cfg.get("domains", {}).items():
        got = False
        for path in ("/", "/.well-known/security.txt"):
            st, body = fetch("https://%s%s" % (dom, path), accept="text/html,text/plain")
            if st == 404 and path != "/":
                a.reading("page", dom + path, True, "absent (404)")
                continue
            if st != 200:
                a.reading("page", dom + path, False, "HTTP %s %s" % (st, body[:120] if st == 0 else ""))
                continue
            got = True
            src = "page:%s%s" % (dom, path)
            a.scan_private(html.unescape(body), persona, "page content", src)
            for kind, rx in FP.items():
                for m in rx.findall(body):
                    val = m if isinstance(m, str) else m[0]
                    val = val.strip()
                    if kind == "comment":
                        a.scan_private(val, persona, "HTML comment", src)
                        continue
                    fps.setdefault((kind, val.lower()), set()).add(dom)
                    if kind in ("email", "author"):
                        a.scan_private(val, persona, kind, src)
                        a.cross_handle(val, persona, kind, src)
        if got:
            a.reading("page", dom, True, "")
    for (kind, val), ds in fps.items():
        if len(ds) > 1:
            ds = sorted(ds)
            a.link(a.cfg["domains"][ds[0]], a.cfg["domains"][ds[1]], "shared-fingerprint",
                   "same %s on both sites" % kind, "page:%s" % ",".join(ds),
                   a.mask(val) if kind == "email" else val, "high")


# ---------------------------------------------------------------- helpers bound to Audit
def _cross_handle(self, text, persona, field, source):
    """Another persona's handle appearing in this persona's public text."""
    low = (text or "").lower()
    for handle, other in self.cfg.get("handles", {}).items():
        if other != persona and handle.lower() in low:
            self.link(persona, other, "handle-mention", field, source,
                      "mentions handle '%s'" % handle, "medium")


def _is_private_val(self, s):
    s = (s or "").lower()
    return any(p["value"].lower() in s for p in self.private)


def _mask(self, s):
    if self.is_private_val(s):
        return "[private identifier]"
    if "@" in s:
        u, d = s.split("@", 1)
        return "%s…@%s" % (u[:2], d)
    return s


Audit.cross_handle = _cross_handle
Audit.is_private_val = _is_private_val
Audit.mask = _mask


# ---------------------------------------------------------------- report
def render(a, scope_problems):
    today = dt.date.today().isoformat()
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = []
    for e in a.evidence:
        sev = a.classify(e)
        rows.append((SEV_ORDER[sev], sev, e))
    rows.sort(key=lambda r: (r[0], r[2]["kind"]))
    crossings = [r for r in rows if r[1] != "INFO"]
    failed = [r for r in a.readings if not r[2]]

    if scope_problems:
        bluf = "**SCOPE UNCONFIRMED** — not run. Missing from registry: %s." % "; ".join(scope_problems)
    elif crossings:
        worst = crossings[0]
        bluf = "**%s** — %d link(s) cross a declared separation. Worst: %s (%s)." % (
            worst[1], len(crossings), worst[2]["kind"], worst[2]["field"])
    else:
        bluf = "No cross-separation links found."
    if failed and not scope_problems:
        bluf += " **%d reading(s) FAILED — this is not an all-clear for those sources.**" % len(failed)

    fm = dict(a.cfg.get("note_frontmatter", {}))
    L = ["---"] + ["%s: %s" % kv for kv in fm.items()] + [
         "updated: %s" % today, "tags: [opsec, linkage, 镜]", "---", ""]
    if a.cfg.get("note_links"):
        L += [" · ".join(a.cfg["note_links"]), ""]
    L += ["## " + a.cfg.get("summary_heading", "Summary"), "", bluf, "",
         "Run %s. Separation map:" % now, ""]
    for cname, members in a.cfg["clusters"].items():
        L.append("- **%s**: %s" % (cname, ", ".join(members)))
    L += ["", "## Cross-separation links", ""]
    if crossings:
        L += ["| Sev | Link | Kind | Evidence field | Source | Value |",
              "|---|---|---|---|---|---|"]
        for _, sev, e in crossings:
            L.append("| %s | %s ↔ %s | %s | %s | %s | %s |" % (
                sev, e["a"], e["b"], e["kind"], e["field"], e["source"],
                str(e["value"]).replace("|", "/")))
    else:
        L.append("None found in the sources that were read.")
    L += ["", "## Same-cluster links (deliberate, for reference)", ""]
    same = [r for r in rows if r[1] == "INFO"]
    for _, _, e in same:
        L.append("- %s ↔ %s · %s · %s · `%s`" % (e["a"], e["b"], e["field"], e["source"], e["value"]))
    if not same:
        L.append("- none")
    L += ["", "## Readings", ""]
    for src, tgt, ok, det in a.readings:
        L.append("- %s `%s` %s %s" % ("✅" if ok else "❌ FAILED", src, tgt, det))
    L += ["", "## Manual checks (no public API — do by hand)", ""]
    for item in a.cfg.get("manual_checks", []):
        L.append("- [ ] %s" % item)
    L += ["", "## History", "", "- %s — %d cross-separation, %d failed readings" % (
        now, len(crossings), len(failed)), ""]
    return "\n".join(L), (2 if (scope_problems or failed) else (1 if crossings else 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--registry", help="override registry path from config")
    ap.add_argument("--out", help="write markdown note here (else stdout)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", help="comma list: github,rdap,dns,ct,page")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    a = Audit(cfg)
    scope = check_scope(cfg, args.registry or cfg["registry"])
    if not scope:
        steps = {"github": audit_github, "rdap": audit_rdap, "dns": audit_dns,
                 "ct": audit_ct, "page": audit_pages}
        only = args.only.split(",") if args.only else list(steps)
        for k in only:
            try:
                steps[k](a)
            except Exception as e:  # a crashed check is a failed reading, loudly
                a.reading(k, "*", False, "check crashed: %s: %s" % (type(e).__name__, e))
    if args.json:
        print(json.dumps({"scope_problems": scope, "readings": a.readings,
                          "evidence": [dict(e, severity=a.classify(e)) for e in a.evidence]},
                         indent=2, ensure_ascii=False))
        return 2 if scope else 0
    note, code = render(a, scope)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(note)
    else:
        print(note)
    return code


if __name__ == "__main__":
    sys.exit(main())
