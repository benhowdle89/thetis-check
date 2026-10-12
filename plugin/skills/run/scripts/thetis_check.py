#!/usr/bin/env python3
"""Thetis free check: 14 basic production-readiness checks, as plain static analysis.

Usage: thetis_check.py [repo-path] [--offline] [--no-gitleaks] [--out DIR] [--json]

- Read-only. Writes nothing inside the repository. The report goes to
  ~/.thetis-check/reports/ (or --out) and is printed.
- No AI. Every rating comes from the rules in this file.
- Network: only check 12 (npm audit), which sends your dependency list (package
  names and versions, never code) to the npm registry. --offline skips it.
- Secret values are never printed or saved: findings say where, never what.

Ratings: R needs fixing · A weak spot · OK nothing found by this basic check ·
NV not checked (needs a person, your dashboards, or the full review) · — doesn't apply.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time

VERSION = "0.1.0"
SITE = "https://thetis.benhowdle.im"
EMAIL = "hello@benhowdle.im"

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".nuxt", ".svelte-kit", "coverage", "vendor",
             ".venv", "venv", "__pycache__", ".turbo", ".wrangler", ".vercel", "out", "target", ".cache"}
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".php", ".java", ".kt", ".swift",
            ".vue", ".svelte", ".astro", ".toml", ".yaml", ".yml", ".json", ".sql", ".rules", ".md", ".html", ".sh"}
CODE_EXT = TEXT_EXT - {".md", ".json", ".yaml", ".yml", ".toml", ".html", ".sql"}
MAX_FILE = 1_000_000
# Data files (dumps, exports, local databases) are never opened: they may hold real people's data.
# SQL is only read when it's a migration or schema, never a dump.
DATA_FILE = re.compile(r"\.(sql|csv|tsv|sqlite3?|db|dump|bak|xlsx?|parquet|jsonl|ndjson)$", re.I)
SCHEMA_SQL = re.compile(r"(^|/)(migrations?|schema|drizzle|prisma|supabase/migrations)(/|$)|schema\.sql$", re.I)
# Folders that don't run in production. Checks about the live app's behaviour skip them.
NOT_APP = re.compile(r"(^|/)(scripts?|tests?|__tests__|spec|e2e|evals?|bench(marks?)?|fixtures?|examples?|docs?|tools?)(/)", re.I)
GENERATED = re.compile(r"(^|/)(_generated|generated|__generated__|gen)/|\.generated\.|\.min\.js$|\.d\.ts$")

# Key patterns: (name, regex, live?). Live keys are red; test or low-impact keys amber.
SECRET_PATTERNS = [
    ("Stripe live secret key", r"\bsk_live_[0-9a-zA-Z]{20,}", True),
    ("Stripe live restricted key", r"\brk_live_[0-9a-zA-Z]{20,}", True),
    ("Stripe test secret key", r"\bsk_test_[0-9a-zA-Z]{20,}", False),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", True),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}", True),
    ("OpenAI key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}", True),
    ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_-]{30,}", True),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{20,}", True),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}", True),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", True),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", False),
]
SECRET_RES = [(n, re.compile(p), live) for n, p, live in SECRET_PATTERNS]
PLACEHOLDER = re.compile(r"(x{6,}|0{8,}|your[_-]?key|example|placeholder|dummy|changeme|<[^>]+>)", re.I)
SECRET_FILE = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|\.dev\.vars|\.envrc|id_rsa|id_ed25519|[\w.-]+\.pem|[\w.-]+\.p12|serviceAccount[\w.-]*\.json)$")
TEMPLATE_FILE = re.compile(r"\.(example|sample|template|dist|defaults?)$|example", re.I)

NAMES = {
    "01": "Secrets in code history", "02": "Secrets in the app", "03": "Who can call what",
    "04": "Who can see what", "05": "Files and uploads", "06": "Personal data", "07": "Payment messages",
    "08": "Prices and access", "09": "Test and live apart", "10": "Backups exist", "11": "Restore rehearsed",
    "12": "Dependencies", "13": "Abuse and runaway cost", "14": "Who can change production",
}
SEVERITY = {"R": 4, "A": 3, "NV": 2, "OK": 1, "—": 0}


# --- repository access (read-only) -------------------------------------------

class Repo:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.is_git = subprocess.run(["git", "-C", self.root, "rev-parse", "--git-dir"],
                                     capture_output=True).returncode == 0
        self.files = self._files()
        self._text = {}
        self.pkg = self._json("package.json") or {}
        deps = {}
        for k in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(self.pkg.get(k) or {})
        self.deps = deps
        self.prod_deps = dict(self.pkg.get("dependencies") or {})

    def git(self, *args, **kw):
        return subprocess.run(["git", "-C", self.root, *args], capture_output=True, text=True, errors="replace", **kw)

    def _files(self):
        if self.is_git:
            out = self.git("ls-files", "-z").stdout
            return sorted(f for f in out.split("\0") if f and not (set(f.split("/")) & SKIP_DIRS))
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                found.append(os.path.relpath(os.path.join(dirpath, fn), self.root))
        return sorted(found)

    def text(self, rel):
        if rel not in self._text:
            path = os.path.join(self.root, rel)
            try:
                if os.path.getsize(path) > MAX_FILE:
                    self._text[rel] = ""
                else:
                    with open(path, "r", errors="replace") as f:
                        self._text[rel] = f.read()
            except OSError:
                self._text[rel] = ""
        return self._text[rel]

    def _json(self, rel):
        try:
            with open(os.path.join(self.root, rel)) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def code_files(self, exts=CODE_EXT):
        return [f for f in self.files if os.path.splitext(f)[1].lower() in exts
                and not SECRET_FILE.search(f) and not GENERATED.search(f)
                and not (DATA_FILE.search(f) and not (f.lower().endswith(".sql") and SCHEMA_SQL.search(f)
                                                      and not re.search(r"backup|dump|export", f, re.I)))]

    def grep(self, pattern, exts=CODE_EXT, flags=0, limit=50, app_only=False):
        """[(file, line_no, line)] for a regex across tracked text files. Never reads secret or data files.
        app_only skips scripts, tests and other code that doesn't run in production."""
        rx = re.compile(pattern, flags)
        hits = []
        for f in self.code_files(exts):
            if app_only and NOT_APP.search(f):
                continue
            for i, line in enumerate(self.text(f).splitlines(), 1):
                if rx.search(line):
                    hits.append((f, i, line.strip()[:160]))
                    if len(hits) >= limit:
                        return hits
        return hits

    def has_dep(self, *names):
        return [n for n in names if n in self.deps]


def where(hits, n=5):
    shown = [f"{f}:{i}" for f, i, _ in hits[:n]]
    more = f" and {len(hits) - n} more" if len(hits) > n else ""
    return ", ".join(shown) + more


class Result:
    def __init__(self, cid):
        self.id, self.name = cid, NAMES[cid]
        self.status, self.found, self.meaning, self.unseen = None, [], "", ""

    def rate(self, status):
        if self.status is None or SEVERITY[status] > SEVERITY[self.status]:
            self.status = status


# --- the 14 checks ---------------------------------------------------------------

def check_01(repo, opts):
    r = Result("01")
    r.unseen = "Whether a key that was found still works. Removing a key from git doesn't switch it off; only replacing it in the provider's dashboard does."
    if not repo.is_git:
        r.rate("NV"); r.found.append("Not a git repository, so history couldn't be checked.")
        return r
    # Secret files ever committed (current or deleted).
    added = repo.git("log", "--all", "--diff-filter=A", "--name-only", "--format=").stdout.split("\n")
    secret_files = sorted({f for f in added if f and SECRET_FILE.search(f) and not TEMPLATE_FILE.search(f)})
    if secret_files:
        r.rate("R")
        r.found.append(f"Secret files were committed at some point: {', '.join(secret_files[:8])}"
                       f"{' and more' if len(secret_files) > 8 else ''}. Their contents were not read.")
    hits, scanned, partial = scan_history(repo, opts)
    for (name, f, commit), live in sorted(hits.items()):
        r.rate("R" if live else "A")
        r.found.append(f"{name} in {f} (commit {commit[:8]}). The value was not printed.")
    if not secret_files and not hits:
        r.rate("OK" if not partial else "NV")
        r.found.append(f"No known key patterns or secret files found in {scanned}." if not partial
                       else f"Nothing found in the part of history scanned ({scanned}); the scan stopped early.")
    elif partial:
        r.found.append(f"The history scan stopped early ({scanned}).")
    r.meaning = ("Anyone who has ever had a copy of the code can read a key saved in its history, "
                 "even if it was deleted later.")
    return r


def scan_history(repo, opts):
    """{(pattern, file, commit): live}. Uses gitleaks when installed, else a pattern scan of git log -p."""
    hits = {}
    if shutil.which("gitleaks") and not opts["no_gitleaks"]:
        report = os.path.join(os.path.expanduser("~/.thetis-check"), f"gitleaks-{os.getpid()}.json")
        os.makedirs(os.path.dirname(report), exist_ok=True)
        sub = ["git"] if subprocess.run(["gitleaks", "git", "--help"], capture_output=True).returncode == 0 else ["detect", "--source"]
        cmd = ["gitleaks", *sub, "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json",
               "--report-path", report]
        cmd.append(repo.root) if sub == ["git"] else cmd.insert(3, repo.root)
        subprocess.run(cmd, capture_output=True)
        try:
            with open(report) as f:
                findings = json.load(f) or []
        finally:
            if os.path.exists(report):
                os.remove(report)
        for g in findings:
            f = g.get("File", "")
            if TEMPLATE_FILE.search(f):
                continue
            rule = g.get("RuleID", "secret")
            live = not re.search(r"test|generic|curl", rule)
            hits[(f"possible {rule}", f, str(g.get("Commit", "")))] = live
        count = repo.git("rev-list", "--all", "--count").stdout.strip() or "?"
        return hits, f"{count} commits (gitleaks)", False
    start, limit_bytes, read = time.time(), opts["max_history_mb"] * 1_000_000, 0
    proc = subprocess.Popen(["git", "-C", repo.root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0"],
                            stdout=subprocess.PIPE, text=True, errors="replace")
    commit, path, commits, partial = "", "", 0, False
    for line in proc.stdout:
        read += len(line)
        if line.startswith("commit "):
            commit, commits = line.split()[1], commits + 1
        elif line.startswith("+++ b/"):
            path = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++") and path and not TEMPLATE_FILE.search(path):
            for name, rx, live in SECRET_RES:
                m = rx.search(line)
                if m and not PLACEHOLDER.search(m.group(0)):
                    hits[(name, path, commit)] = live
        if read > limit_bytes or time.time() - start > opts["max_history_seconds"]:
            partial = True
            proc.kill()
            break
    proc.wait()
    return hits, f"{commits} commits (pattern scan)", partial


def check_02(repo, opts):
    r = Result("02")
    r.meaning = "Anything sent to the browser or the mobile app can be read by anyone who uses it."
    r.unseen = "The built app itself and your live logs. Only the source code was checked."
    exposed = repo.grep(r"\b(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*"
                        r"(SECRET|PRIVATE|SERVICE_ROLE|ADMIN|PASSWORD|SIGNING|WEBHOOK)[A-Z0-9_]*",
                        exts=CODE_EXT | {".json", ".toml", ".yaml", ".yml"})
    if exposed:
        r.rate("R")
        r.found.append(f"Secret-sounding settings are exposed to the browser at {where(exposed)}.")
    logged = repo.grep(r"console\.(log|info|debug)\(.*\b(password|secret|token|authorization|apiKey|api_key)\b",
                       flags=re.I, app_only=True)
    if logged:
        r.rate("A")
        r.found.append(f"Passwords, tokens or keys may be written to logs at {where(logged)}.")
    if not r.found:
        r.rate("OK")
        r.found.append("No secret-sounding browser settings and no obvious logging of tokens or passwords.")
    return r


def check_03(repo, opts):
    r = Result("03")
    r.meaning = "Every private function of your app should refuse anyone who isn't logged in, and admin areas should refuse ordinary users."
    r.unseen = "Whether each route actually checks the login. That needs someone to read the code, which the full review does."
    bypass = repo.grep(r"""(===?|==)\s*['"](bypass|backdoor|letmein|debug[-_]?token|test[-_]?token|admin123)['"]""", flags=re.I, app_only=True)
    if bypass:
        r.rate("A")
        r.found.append(f"A hard-coded bypass value appears at {where(bypass)}.")
    unsafe_default = repo.grep(r"(ENVIRONMENT|NODE_ENV|APP_ENV|ENV)\b[^\n]{0,40}(\|\||\?\?)\s*['\"](development|dev|local)['\"]", app_only=True)
    if unsafe_default:
        r.rate("A")
        r.found.append(f"The app assumes it's in development when no environment is set, at {where(unsafe_default)}. "
                       "If production ever loses that setting, development shortcuts switch on.")
    admin = repo.grep(r"""['"`]/(api/)?(admin|debug|internal|seed|_debug)(/|['"`])""", limit=100, app_only=True)
    if admin:
        count = f"{'At least ' if len(admin) >= 100 else ''}{len(admin)}"
        r.found.append(f"{count} references to admin, debug or internal routes, for example at {where(admin, 3)}. "
                       "Each one should require an admin login.")
    if r.status is None:
        r.rate("NV")
    if not r.found:
        r.found.append("No obvious bypasses or unsafe defaults. Route-by-route protection isn't something a basic check can confirm.")
    return r


def check_04(repo, opts):
    r = Result("04")
    r.meaning = "Being logged in isn't enough: each person should only be able to see and change their own data."
    r.unseen = "Whether each query checks who owns the record. The full review traces that route by route."
    rls_off = repo.grep(r"disable\s+row\s+level\s+security", exts={".sql"}, flags=re.I)
    if rls_off:
        r.rate("R")
        r.found.append(f"Database row-level protection is switched off at {where(rls_off)}.")
    open_rules = repo.grep(r"allow\s+(read|write|read,\s*write)\s*:\s*if\s+true", exts={".rules", ".json"}, flags=re.I)
    if open_rules:
        r.rate("R")
        r.found.append(f"Database rules allow anyone to read or write at {where(open_rules)}.")
    weak_ids = repo.grep(r"Math\.random\(\).*\b(token|id|code|secret|key|invite|slug|nonce)\b|"
                         r"\b(token|id|code|secret|key|invite|slug|nonce)\b.*Math\.random\(\)", flags=re.I, app_only=True)
    if weak_ids:
        r.rate("A")
        r.found.append(f"Math.random appears to make tokens or ids at {where(weak_ids)}. These can be guessed.")
    if r.status is None:
        r.rate("NV")
        r.found.append("No database rules switched off, no open rules, and no guessable token generators found.")
    return r


def check_05(repo, opts):
    r = Result("05")
    r.meaning = "Files people upload (photos, documents, waivers) shouldn't be readable by strangers."
    r.unseen = "Your storage provider's actual settings, which live in its dashboard."
    public = repo.grep(r"public\s*:\s*true|getPublicUrl\(|ACL\s*:\s*['\"]public-read|\.r2\.dev\b|allow\s+read\s*:\s*if\s+true",
                       exts=CODE_EXT | {".toml", ".json", ".yaml", ".yml", ".rules"})
    storage_used = repo.has_dep("@supabase/supabase-js", "firebase", "firebase-admin", "@aws-sdk/client-s3", "aws-sdk",
                                "uploadthing", "cloudinary", "@vercel/blob") or repo.grep(r"\bR2Bucket\b|r2_buckets", limit=1)
    if public:
        r.rate("A")
        r.found.append(f"Public storage settings or permanent public file links appear at {where(public)}.")
    elif storage_used:
        r.rate("NV")
        r.found.append("The app stores files, but whether they're private is set in your storage dashboard.")
    else:
        r.rate("—")
        r.found.append("No file storage found.")
    return r


def check_06(repo, opts):
    r = Result("06")
    r.meaning = "Copies of real people's data in the code repository are readable by everyone who has the code, forever."
    r.unseen = "Whether you can delete or export one person's data end to end, and what goes to your analytics tools."
    dump_ext = {".sqlite", ".sqlite3", ".db", ".dump", ".bak", ".xlsx", ".csv", ".sql"}
    risky = []
    for f in repo.files:
        ext = os.path.splitext(f)[1].lower()
        if ext not in dump_ext:
            continue
        lower = f.lower()
        if ext == ".sql" and re.search(r"migration|schema|seed|drizzle|prisma|supabase/", lower):
            continue
        try:
            size = os.path.getsize(os.path.join(repo.root, f))
        except OSError:
            size = 0
        if ext in {".sqlite", ".sqlite3", ".db", ".dump", ".bak"} or re.search(r"backup|dump|export|prod|user|customer|report", lower) \
                or size > 200_000:
            risky.append(f)
    deleted = []
    if repo.is_git:
        removed = repo.git("log", "--all", "--diff-filter=D", "--name-only", "--format=").stdout.split("\n")
        deleted = sorted({f for f in removed if f and os.path.splitext(f)[1].lower() in {".sqlite", ".sqlite3", ".db", ".dump", ".bak"}
                          or re.search(r"(backup|dump).*\.(sql|csv)$", f, re.I)})
    if risky:
        r.rate("R")
        r.found.append(f"Database copies or data exports are committed: {', '.join(risky[:8])}{' and more' if len(risky) > 8 else ''}. "
                       "Their contents were not read.")
    if deleted:
        r.rate("A")
        r.found.append(f"Database copies were committed and later deleted, so they remain in history: {', '.join(deleted[:5])}"
                       f"{' and more' if len(deleted) > 5 else ''}.")
    logs = repo.grep(r"console\.(log|info)\(.*\b(email|phone|address|dob|date_of_birth)\b", flags=re.I, app_only=True)
    if logs:
        r.rate("A")
        r.found.append(f"Personal details may be written to logs at {where(logs)}.")
    if r.status is None:
        r.rate("NV")
        r.found.append("No committed data copies and no obvious logging of personal details.")
    return r


def check_07(repo, opts):
    r = Result("07")
    payments = repo.has_dep("stripe", "@stripe/stripe-js", "@paddle/paddle-node-sdk", "@lemonsqueezy/lemonsqueezy.js",
                            "react-native-purchases", "@revenuecat/purchases-js")
    if not payments:
        r.rate("—"); r.found.append("No payment library found.")
        return r
    r.meaning = "Your app should only believe payment messages that really came from the payment provider, and count each one once."
    r.unseen = "Whether a repeated message could grant something twice. The full review checks that."
    verify = repo.grep(r"constructEvent(Async)?\(|webhooks\.constructEvent|verifyHeader\(|verifyWebhook|webhooks\.unwrap\(", app_only=True)
    webhook = repo.grep(r"webhook", flags=re.I, limit=200, app_only=True)
    if verify:
        r.rate("OK")
        r.found.append(f"Payment webhook signatures are verified ({where(verify, 2)}).")
    elif webhook:
        r.rate("R")
        r.found.append(f"Payment webhooks are handled (for example {where(webhook, 2)}) but no signature check was found.")
    else:
        r.rate("NV")
        r.found.append(f"Uses {', '.join(payments)}, but no webhook handler was found.")
    return r


def check_08(repo, opts):
    r = Result("08")
    if not repo.has_dep("stripe", "@paddle/paddle-node-sdk", "@lemonsqueezy/lemonsqueezy.js", "react-native-purchases"):
        r.rate("—"); r.found.append("No payment library found.")
        return r
    r.meaning = "Customers shouldn't be able to choose their own price or reach paid features without paying."
    r.unseen = "Every route into a paid feature. The full review checks each one."
    client_price = repo.grep(r"(unit_amount|amount)\s*:\s*(req\.body|body\.|request\.body|input\.|params\.|args\.)", app_only=True)
    if client_price:
        r.rate("R")
        r.found.append(f"A payment amount may come from the customer's request at {where(client_price)}.")
    else:
        r.rate("NV")
        r.found.append("No sign of prices taken from the customer's request.")
    return r


def check_09(repo, opts):
    r = Result("09")
    r.meaning = "Test versions of the app shouldn't touch real money or real data, and the live app shouldn't run on test settings."
    r.unseen = "Your hosting settings for preview and test deployments."
    if repo.has_dep("stripe") and repo.grep(r"constructEvent", limit=1) and not repo.grep(r"\blivemode\b", limit=1):
        r.rate("A")
        r.found.append("Payment webhooks don't check whether a message is from test or live mode (no livemode check).")
    if r.status is None:
        r.rate("NV")
        r.found.append("Nothing obvious mixes test and live.")
    return r


def provider_hint(repo):
    hints = []
    if repo.has_dep("@supabase/supabase-js"):
        hints.append("Supabase: Database → Backups (point-in-time recovery needs a paid plan)")
    if repo.grep(r"d1_databases|\bD1Database\b", exts=CODE_EXT | {".toml", ".json"}, limit=1):
        hints.append("Cloudflare D1: Time Travel, whose retention depends on your plan")
    if repo.has_dep("@neondatabase/serverless"):
        hints.append("Neon: branch history and restore window")
    if repo.has_dep("@planetscale/database"):
        hints.append("PlanetScale: backup schedule")
    if repo.has_dep("firebase", "firebase-admin"):
        hints.append("Firebase: Firestore has no automatic backups unless you schedule them")
    if repo.has_dep("pg", "postgres", "prisma", "@prisma/client", "drizzle-orm", "mysql2", "mongoose"):
        hints.append("your database host's backup settings")
    return hints


def check_10(repo, opts):
    r = Result("10")
    r.rate("NV")
    r.meaning = "If your database were deleted today, a recent copy should exist that the app itself can't delete."
    r.unseen = "Backups are set in your provider's dashboard, so code can't confirm them."
    hints = provider_hint(repo)
    r.found.append("Check " + "; ".join(hints) + "." if hints else "Check your database provider's backup settings.")
    scripts = [k for k, v in (repo.pkg.get("scripts") or {}).items() if re.search(r"backup|export|dump", k + " " + str(v), re.I)]
    if scripts:
        r.found.append(f"Backup scripts exist ({', '.join(scripts[:3])}), but a script someone has to remember to run isn't an automatic backup.")
    return r


def check_11(repo, opts):
    r = Result("11")
    r.rate("NV")
    r.meaning = "A backup nobody has restored is a hope, not a plan: you don't know how long it takes or whether it works."
    r.unseen = "Whether anyone has restored a backup. Only you can answer that."
    docs = [f for f in repo.files if f.lower().endswith(".md") and re.search(r"\brestor(e|ing)\b", repo.text(f), re.I)
            and re.search(r"backup|database|point.in.time|time travel", repo.text(f), re.I)]
    r.found.append(f"Restore steps are written down in {', '.join(docs[:3])}." if docs else "No written restore steps were found.")
    return r


SENSITIVE_PKG = re.compile(r"(jwt|jose|jsonwebtoken|passport|oauth|auth|session|cookie|crypto|bcrypt|argon|stripe|"
                           r"sanitize|dompurify|xss|helmet|cors|multer|busboy|formidable|express|next|hono|fastify|axios|undici)", re.I)


def check_12(repo, opts):
    r = Result("12")
    r.meaning = "Code libraries with published security holes are the easiest way in, especially ones that handle logins or payments."
    r.unseen = "Whether your app actually uses the vulnerable part of each library."
    if not repo.pkg:
        r.rate("NV"); r.found.append("No package.json at the top of the repository. This version only checks npm projects.")
        return r
    if opts["offline"]:
        r.rate("NV"); r.found.append("Skipped (--offline).")
        return r
    if not shutil.which("npm") or not os.path.exists(os.path.join(repo.root, "package-lock.json")):
        r.rate("NV"); r.found.append("Needs npm and a package-lock.json to check.")
        return r
    out = subprocess.run(["npm", "audit", "--omit=dev", "--json"], cwd=repo.root, capture_output=True, text=True)
    try:
        data = json.loads(out.stdout)
    except ValueError:
        r.rate("NV"); r.found.append("npm audit didn't return a result (offline or registry error).")
        return r
    bad = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = v.get("severity")
        if sev not in ("critical", "high", "moderate"):
            continue
        n_adv = sum(isinstance(x, dict) for x in v.get("via", []))
        if not n_adv:
            continue
        direct = bool(v.get("isDirect"))
        flag = bool(SENSITIVE_PKG.search(name))
        status = "R" if direct and (sev == "critical" or (sev == "high" and flag)) else "A"
        bad.append((status, sev, name, n_adv, direct))
    for status, sev, name, n_adv, direct in sorted(bad, key=lambda b: (-SEVERITY[b[0]], b[2])):
        r.rate(status)
    if bad:
        top = sorted(bad, key=lambda b: (-SEVERITY[b[0]], ["critical", "high", "moderate"].index(b[1])))[:8]
        r.found.append(f"{len(bad)} libraries with known holes at moderate or above: " +
                       "; ".join(f"{n} ({s}, {'direct' if d else 'via another library'})" for _, s, n, _, d in top) +
                       (" and more." if len(bad) > 8 else "."))
    else:
        r.rate("OK")
        r.found.append("npm audit found no moderate, high or critical holes in production libraries.")
    return r


def check_13(repo, opts):
    r = Result("13")
    paid = repo.has_dep("openai", "@anthropic-ai/sdk", "@google/generative-ai", "@google/genai", "ai", "langchain",
                        "@langchain/core", "replicate", "@aws-sdk/client-bedrock-runtime", "groq-sdk", "@mistralai/mistralai",
                        "twilio", "resend", "@sendgrid/mail", "postmark", "nodemailer")
    # Paid APIs called directly over HTTP, without their SDK.
    for host, label in (("api.openai.com", "OpenAI (direct API)"), ("api.anthropic.com", "Anthropic (direct API)"),
                        ("generativelanguage.googleapis.com", "Gemini (direct API)"), ("api.twilio.com", "Twilio (direct API)")):
        if label.split()[0].lower() not in " ".join(paid).lower() and repo.grep(re.escape(host), limit=1, app_only=True):
            paid = paid + [label]
    if not paid:
        r.rate("NV")
        r.found.append("No AI, email or SMS libraries found. Spending caps on your hosting are still worth checking.")
        r.meaning = "One bot or bug shouldn't be able to run up a huge bill."
        r.unseen = "Spending caps, which live in each provider's dashboard."
        return r
    r.meaning = "Features that cost money per use (AI, email, SMS) need limits, or one bot or bug can run up a huge bill."
    r.unseen = "Spending caps and alerts, which live in each provider's dashboard."
    limits = repo.grep(r"rate.?limit|ratelimit|throttl|@upstash/ratelimit|express-rate-limit|limiter", flags=re.I, limit=5, app_only=True)
    warnings = repo.grep(r"console\.(warn|error)\(.*\b(rate.?limit|cost|spend|budget|token.?limit|governor|quota)\b.*\b(off|disabled|unbounded|uncapped|no limit)\b"
                         r"|console\.(warn|error)\(.*\b(unbounded|uncapped)\b.*\b(spend|cost)\b", flags=re.I, app_only=True)
    if warnings:
        r.rate("A")
        r.found.append(f"The app warns about its own missing limits at {where(warnings)}. Check those are switched on in production.")
    if not limits:
        r.rate("R")
        r.found.append(f"Uses paid services ({', '.join(paid[:5])}) and no rate limiting was found anywhere.")
    else:
        r.rate("NV")
        r.found.append(f"Uses paid services ({', '.join(paid[:5])}); rate limiting appears at {where(limits, 2)}. "
                       "Whether it covers every paid route needs checking.")
    return r


PROD_WRITE = re.compile(
    r"wrangler\s+(deploy|publish|secret|d1\s+(execute|migrations\s+apply)[^\n]*--remote|r2|kv)|--remote\b|vercel\b[^\n]*(--prod|deploy)"
    r"|netlify\s+deploy[^\n]*--prod|fly(ctl)?\s+deploy|railway\s+up|supabase\s+(db\s+push|functions\s+deploy|secrets)"
    r"|prisma\s+(migrate\s+deploy|db\s+push)|drizzle-kit\s+(push|migrate)|terraform\s+apply|kubectl\s+(apply|delete)"
    r"|firebase\s+deploy|git\s+push|npm\s+publish|serverless\s+deploy|sst\s+deploy", re.I)
NON_PROD = re.compile(r"stag(e|ing)|preview|\bdev\b|\blocal\b|\btest\b", re.I)


def check_14(repo, opts):
    r = Result("14")
    r.meaning = "Something mechanical, not just good intentions, should stop a mistake by a person, a pipeline or an AI assistant reaching the live app."
    r.unseen = "Branch protection, deploy approvals and who holds production access. Those are set in GitHub and your hosting dashboards."
    writes = [(k, v) for k, v in (repo.pkg.get("scripts") or {}).items()
              if PROD_WRITE.search(str(v)) and not (NON_PROD.search(f"{k} {v}") and not re.search("prod", f"{k} {v}", re.I))]
    settings = [p for p in (".claude/settings.json", ".claude/settings.local.json") if p in repo.files
                or os.path.exists(os.path.join(repo.root, p))]
    allow, deny, mode = [], [], None
    for p in settings:
        s = repo._json(p) or {}
        perms = s.get("permissions") or {}
        allow += perms.get("allow") or []
        deny += perms.get("deny") or []
        mode = perms.get("defaultMode") or mode
    if mode == "bypassPermissions":
        r.rate("R"); r.found.append("Claude Code is set to run any command without asking (bypassPermissions).")
    if any(re.fullmatch(r"Bash(\(\*\))?", a) for a in allow):
        r.rate("R" if not deny else "A"); r.found.append("Claude Code is allowed to run any shell command without asking.")
    if writes:
        names = ", ".join(k for k, _ in writes[:5])
        covered = [k for k, v in writes if any(k in d or str(v).split()[0] in d for d in deny)]
        if not deny:
            r.rate("A")
            r.found.append(f"Scripts that change production ({names}) have no Claude Code deny rule, so one approval is all that stands in the way.")
        elif len(covered) < len(writes):
            r.rate("A")
            r.found.append("Some production scripts aren't covered by a Claude Code deny rule.")
        else:
            r.found.append("Production scripts are covered by Claude Code deny rules.")
    for wf in [f for f in repo.files if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))]:
        text = repo.text(wf)
        if PROD_WRITE.search(text) and not re.search(r"^\s*environment\s*:", text, re.M):
            r.rate("A")
            r.found.append(f"{wf} deploys with no approval step (no GitHub environment).")
    if r.status is None:
        r.rate("NV")
        if not r.found:
            r.found.append("No production write paths found in scripts, CI or Claude Code settings.")
    return r


CHECKS = [check_01, check_02, check_03, check_04, check_05, check_06, check_07,
          check_08, check_09, check_10, check_11, check_12, check_13, check_14]


# --- report --------------------------------------------------------------------

def overall(results):
    statuses = [r.status for r in results]
    nv = statuses.count("NV")
    if "R" in statuses:
        return f"RED FLAGS FOUND ({statuses.count('R')} need fixing, {nv} not checked)"
    if "A" in statuses:
        return f"WEAK SPOTS FOUND ({statuses.count('A')} weak spots, {nv} not checked)"
    return f"NO RED FLAGS FOUND BY THE BASIC CHECK ({nv} not checked). That isn't the same as safe."


def render(repo, results, started):
    name = os.path.basename(repo.root)
    commit = repo.git("rev-parse", "--short", "HEAD").stdout.strip() if repo.is_git else "not a git repo"
    lines = [f"# Thetis free check: {name}", "",
             f"**{overall(results)}**", "",
             "| " + " | ".join(r.id for r in results) + " |", "|" + "---|" * len(results),
             "| " + " | ".join(r.status for r in results) + " |", "",
             "R needs fixing · A weak spot · OK nothing found by this basic check · NV not checked · — doesn't apply", ""]
    order = sorted(results, key=lambda r: (-SEVERITY[r.status], r.id))
    for r in order:
        lines.append(f"## {r.id} {r.name}: {r.status}")
        if r.meaning and r.status in ("R", "A"):
            lines.append(f"*Why it matters:* {r.meaning}")
        for f in r.found:
            lines.append(f"- {f}")
        if r.unseen and r.status != "—":
            lines.append(f"- *Not checked here:* {r.unseen}")
        lines.append("")
    took = time.time() - started
    lines += ["---", "",
              "This is a basic, automatic check: plain scripts, no AI, read-only. It finds common warning signs; it can't "
              "prove an app is safe, and it can't see your dashboards. \"OK\" means only that this check found nothing.", "",
              f"**Want the full review?** A person reads the code behind every check, confirms each finding, and gives you a "
              f"plain-English report with fixes you only pay for when their tests pass: {SITE} · {EMAIL}", "",
              f"*{name} at {commit} · Thetis free check {VERSION} · {datetime.date.today().isoformat()} · {took:.0f}s*"]
    return "\n".join(lines) + "\n"


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = {a.split("=")[0]: (a.split("=", 1)[1] if "=" in a else True) for a in argv if a.startswith("--")}
    unknown = set(flags) - {"--offline", "--no-gitleaks", "--out", "--json"}
    if unknown or len(args) > 1:
        sys.exit(__doc__)
    root = args[0] if args else "."
    if not os.path.isdir(root):
        sys.exit(f"Not a directory: {root}")
    opts = {"offline": "--offline" in flags, "no_gitleaks": "--no-gitleaks" in flags,
            "max_history_mb": 400, "max_history_seconds": 90}
    started = time.time()
    repo = Repo(root)
    results = []
    for check in CHECKS:
        cid = check.__name__.split("_")[1]
        note = " (scanning all of git history; this can take a few minutes on a large repo)" if cid == "01" else ""
        print(f"Checking {cid} {NAMES[cid]}{note}...", file=sys.stderr, flush=True)
        try:
            results.append(check(repo, opts))
        except Exception as e:  # one broken check must not sink the report
            r = Result(check.__name__.split("_")[1])
            r.rate("NV")
            r.found.append(f"This check couldn't run ({type(e).__name__}).")
            results.append(r)
    report = render(repo, results, started)
    out_dir = os.path.expanduser(flags["--out"] if isinstance(flags.get("--out"), str) else "~/.thetis-check/reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(out_dir, f"{os.path.basename(repo.root)}-{stamp}.md")
    with open(path, "w") as f:
        f.write(report)
    if "--json" in flags:
        print(json.dumps([{"id": r.id, "name": r.name, "status": r.status, "found": r.found} for r in results], indent=2))
    else:
        print(report)
        print(f"Saved to {path}")


if __name__ == "__main__":
    main(sys.argv[1:])
