#!/usr/bin/env python3
"""
skill-audit static scanner — sanitizing firewall for Claude Code skills.

Security design: this script reads all target content so Claude never has to.
Prompt injection findings are redacted before they reach Claude's context.

Usage:
  python scanner.py <path>                     # scan local skill directory
  python scanner.py https://github.com/...     # scan GitHub repo/subdirectory
  python scanner.py                            # scan all skills in .claude/skills/

Output: JSON to stdout
"""
import base64
from datetime import datetime, timezone
import json
import os
import re
import sys
import urllib.error
import urllib.request


SCANNABLE_EXTENSIONS = {'.md', '.py', '.sh', '.bash', '.js', '.ts', '.yaml', '.yml', '.txt'}

MAX_GITHUB_FILES = 20
MAX_GITHUB_BYTES = 100 * 1024  # 100 KB

# Rule format: (category, severity, pattern, description, false_positive_note)
# NOTE: prompt_injection findings have their snippet and matched text redacted
# before being included in output so they never enter Claude's context.
RULES = [
    # ---- PROMPT INJECTION / INSTRUCTION OVERRIDE ----
    (
        "prompt_injection", "critical",
        r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|prompts?|directives?)",
        "Attempts to override Claude's prior instructions",
        "Unlikely false positive in a skill",
    ),
    (
        "prompt_injection", "critical",
        r"(?i)disregard\s+(all\s+)?(your\s+)?(instructions?|rules?|guidelines?|training|safety)",
        "Attempts to nullify safety guidelines",
        "Unlikely false positive",
    ),
    (
        "prompt_injection", "critical",
        r"(?i)bypass\s+(safety|security|guardrails?|filters?|restrictions?|limitations?)",
        "Instructs Claude to bypass safety mechanisms",
        "May appear in security education describing attacks — check verb tense and intent",
    ),
    (
        "prompt_injection", "critical",
        r"(?i)do\s+not\s+(tell|inform|mention|show|disclose)\s+(the\s+)?(user|human)",
        "Instructs Claude to hide actions from the user",
        "Legitimate skills never hide actions",
    ),
    (
        "prompt_injection", "high",
        r"(?i)you\s+are\s+now\s+(a\s+)?(different|new|unrestricted|jailbroken|free|evil|dan)\b",
        "Attempts to redefine Claude's identity maliciously",
        "Check full context for roleplay skills",
    ),
    (
        "prompt_injection", "high",
        r"(?i)(act|behave|pretend|roleplay)\s+as\s+if\s+you\s+(have\s+no|don.t\s+have)\s+(restrictions?|guidelines?|rules?|filters?)",
        "Attempts to remove restrictions via roleplay framing",
        "Legitimate roleplay skills don't remove safety guidelines",
    ),
    (
        "prompt_injection", "medium",
        r"(?i)perform\s+(this\s+)?(action|task|step)\s+(silently|secretly|without\s+(alerting|notifying|telling)\s+(the\s+)?user)",
        "Instructs Claude to act without user awareness",
        "Background automation — verify intent",
    ),

    # ---- CREDENTIAL / SENSITIVE PATH ACCESS ----
    (
        "credential_access", "critical",
        r"(?i)(read|cat|open|access|load|fetch|get|view|display|send|exfiltrate)\b.{0,60}\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)\b",
        "Targets SSH private keys or configuration",
        "SSH management skills may legitimately reference these — check read vs describe",
    ),
    (
        "credential_access", "critical",
        r"(?i)(read|cat|open|access|load|fetch|get|view|display|send|exfiltrate)\b.{0,60}\.aws[/\\](credentials|config)\b",
        "Targets AWS credential files",
        "AWS skills may legitimately reference — check read vs describe",
    ),
    (
        "credential_access", "critical",
        r"(?i)(read|cat|open|access|load|fetch|get|view|display|send|exfiltrate)\b.{0,60}(/etc/passwd|/etc/shadow|/etc/sudoers)\b",
        "Targets Unix system credential files",
        "Security audit skills may scan these — verify purpose",
    ),
    (
        "credential_access", "high",
        r"(?i)(read|cat|open|access|load|fetch|get|view|display|send|collect)\b.{0,60}\.env(rc|\.local|\.prod|\.dev|\.staging)?\b",
        "Targets .env files containing application secrets",
        "Config skills may legitimately read .env files",
    ),
    (
        "credential_access", "high",
        r"(?i)(read|cat|open|access|load|fetch|get|view|display)\b.{0,60}(\.netrc|\.npmrc|\.pypirc|\.gitconfig|\.docker[/\\]config\.json)\b",
        "Targets credential configuration files",
        "DevOps skills may legitimately access these",
    ),
    (
        "credential_access", "high",
        r"(?i)(find|search|look\s+for|scan|locate)\b.{0,60}(password|secret|credential|api.?key|token|private.?key)\b",
        "Searches the filesystem for credentials or secrets",
        "Security scanning skills may do this — check if findings go to user or external",
    ),
    (
        "credential_access", "medium",
        r"(?i)(~|/home/\w+|%USERPROFILE%)[/\\]\.(ssh|aws|gnupg|gpg)\b",
        "References home-directory credential folders",
        "Common in DevOps automation — check intent",
    ),

    # ---- EXFILTRATION ----
    (
        "exfiltration", "critical",
        r"(?i)curl\s+.{0,80}(-d\s|--data[=-]|--data-raw|--data-binary|--upload-file\s|-F\s|--form\s)",
        "Uses curl to POST/upload data (potential exfiltration)",
        "API integration skills use curl POST — verify target URL",
    ),
    (
        "exfiltration", "critical",
        r"(?i)wget\s+.{0,80}(--post-(data|file)|--body-(data|file))",
        "Uses wget to POST data",
        "Legitimate API calls — verify URL is not attacker-controlled",
    ),
    (
        "exfiltration", "critical",
        r"(?i)\b(nc|ncat|netcat)\s+.{0,40}(-e\s|--exec\s|\|)",
        "Uses netcat for potential reverse shell or data pipe",
        "Rare in legitimate skills; very high risk",
    ),
    (
        "exfiltration", "high",
        r"(?i)(requests|httpx|aiohttp|urllib)\.(post|put|patch)\s*\(",
        "Python HTTP write call — potential data exfiltration",
        "API integration skills legitimately POST — check URL and payload",
    ),
    (
        "exfiltration", "high",
        r"(?i)(base64\s+(-e|-w\s*0|--encode)|base64\.b64encode|btoa).{0,40}(curl|wget|nc)\b",
        "Encodes data in base64 and pipes to network tool",
        "Classic exfiltration pattern; rarely legitimate",
    ),
    (
        "exfiltration", "medium",
        r"(?i)(send|upload|transmit|transfer|post|push)\s+(the\s+)?(file|content|output|result|data|secret|key|credential|token)\s+(to|at|via)\s+(http|https|ftp|sftp|s3)\b",
        "Instructs Claude to transmit data to a remote endpoint",
        "Deployment/backup skills may legitimately do this — verify endpoint",
    ),

    # ---- HOOKS & AUTO-EXECUTION ----
    (
        "hooks_autoexec", "critical",
        r"(?i)(register|add|install|create|modify|update)\s+.{0,50}(PreToolUse|PostToolUse|Stop|notification)\s*hook",
        "Attempts to register or modify Claude Code execution hooks",
        "Hooks are a system-level feature; skills should not modify them",
    ),
    (
        "hooks_autoexec", "high",
        r"(?i)(automatically\s+execute|run\s+without\s+(asking|confirmation|approval)|no\s+confirmation\s+(needed|required))",
        "Instructs actions without user confirmation",
        "Automation skills may phrase similarly — verify this doesn't bypass safety prompts",
    ),
    (
        "hooks_autoexec", "high",
        r"(?i)(auto.?run|auto.?exec|auto.?start|auto.?trigger)\s+(this|the)\s+(script|command|action|step)",
        "Instructs auto-execution of commands",
        "Verify user is informed before execution",
    ),
    (
        "hooks_autoexec", "medium",
        r"(?i)on\s+(every|each)\s+(tool\s+call|message|response|invocation)\s+(do|run|execute|perform)",
        "Instructs Claude to execute something on every interaction",
        "Legitimate for monitoring skills — check what is executed",
    ),

    # ---- SETTINGS MODIFICATION ----
    (
        "settings_modification", "critical",
        r"(?i)(write|modify|update|edit|append|overwrite)\s+.{0,60}(settings\.json|\.claude[/\\]settings\.json)\b",
        "Attempts to modify Claude Code settings files",
        "Skills should never modify settings.json",
    ),
    (
        "settings_modification", "high",
        r"(?i)(write|modify|update|edit|append|overwrite)\s+.{0,60}CLAUDE\.md\b",
        "Attempts to modify the project CLAUDE.md",
        "Verify the user explicitly requested CLAUDE.md modification",
    ),
    (
        "settings_modification", "medium",
        r"(?i)(add|insert|append)\s+.{0,60}(to\s+)?(the\s+)?(system\s+prompt|CLAUDE\.md|project\s+instructions?)\b",
        "Attempts to inject content into system-level instructions",
        "Could be legitimate for setup workflows — check user consent",
    ),

    # ---- OBFUSCATION ----
    (
        "obfuscation", "high",
        r"(?i)(eval|exec)\s*\(\s*(base64|atob|decode|decompress|unhex)",
        "Executes decoded/obfuscated payload",
        "Rarely legitimate; very suspicious",
    ),
    (
        "obfuscation", "high",
        r"(?i)atob\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
        "Decodes a hardcoded base64 string (potential hidden payload)",
        "Could be a legitimate encoded asset — check what is decoded",
    ),
    (
        "obfuscation", "medium",
        r"(?i)(String\.fromCharCode|chr\(|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,})",
        "Uses character code encoding to hide strings",
        "Could be in legitimate i18n code — check context",
    ),
    (
        "obfuscation", "medium",
        r"python\s+-c\s+['\"].{0,80}base64.{0,40}decode",
        "Executes a Python one-liner decoding base64",
        "Could be in legitimate automation",
    ),

    # ---- EXCESSIVE PERMISSIONS ----
    (
        "excessive_permissions", "critical",
        r"(?m)^\s*-\s*Bash\s*\(\s*\*\s*\)\s*$",
        "Requests unrestricted Bash access (Bash(*)) in allowed-tools",
        "Only acceptable if the skill explicitly requires arbitrary shell commands",
    ),
    (
        "excessive_permissions", "medium",
        r"(?i)\ballowed-tools\b.{0,200}\bWrite\b",
        "Requests Write tool access — can modify local files",
        "Legitimate for code generation skills; verify purpose matches",
    ),

    # ---- SOCIAL ENGINEERING / DECEPTION ----
    (
        "deception", "critical",
        r"(?i)(lie|deceive|mislead|trick|manipulate)\s+(the\s+)?(user|human|developer)\b",
        "Explicitly instructs deception of the user",
        "Almost never a false positive",
    ),
    (
        "deception", "high",
        r"(?i)make\s+(the\s+)?(user|human)\s+believe\s+(that\s+)?(you\s+are|this\s+is)\b",
        "Instructs Claude to misrepresent itself",
        "Roleplay skills may phrase similarly — check full context",
    ),
    (
        "deception", "high",
        r"(?i)without\s+(the\s+user|user)\s+(knowing|noticing|being\s+aware|seeing|asking)\b",
        "Instructs actions hidden from user",
        "Background automation — verify intent",
    ),
    (
        "deception", "medium",
        r"(?i)(minimize|downplay|hide|conceal|suppress)\s+(the\s+)?(risk|danger|warning|error|issue)\b",
        "Instructs Claude to suppress risk warnings",
        "Could appear in UX polish context — verify not hiding security issues",
    ),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def extract_frontmatter(content):
    """
    Parse YAML frontmatter from markdown content between --- delimiters.
    Returns a dict of extracted fields. Never raises.
    """
    try:
        lines = content.splitlines()
        # Find opening ---
        start = None
        for i, line in enumerate(lines):
            if line.strip() == '---':
                start = i
                break
        if start is None:
            return {}
        # Find closing ---
        end = None
        for i in range(start + 1, len(lines)):
            if lines[i].strip() == '---':
                end = i
                break
        if end is None:
            return {}

        metadata = {}
        current_list_key = None
        for line in lines[start + 1:end]:
            if not line.strip():
                continue
            # List item
            if re.match(r'^\s{2,}-\s', line):
                if current_list_key and isinstance(metadata.get(current_list_key), list):
                    metadata[current_list_key].append(line.strip().lstrip('- ').strip())
                continue
            # Key: value or Key:
            m = re.match(r'^([\w][\w-]*)\s*:\s*(.*)', line)
            if m:
                key, value = m.group(1), m.group(2).strip()
                if value:
                    metadata[key] = value
                    current_list_key = None
                else:
                    metadata[key] = []
                    current_list_key = key
        return metadata
    except Exception:
        return {}


def scan_file(filepath, content):
    """Apply all RULES to file content. Redacts prompt_injection payloads."""
    findings = []
    lines = content.splitlines()
    for category, severity, pattern, description, fp_note in RULES:
        try:
            for m in re.finditer(pattern, content, re.MULTILINE):
                line_num = content[:m.start()].count('\n') + 1
                raw_snippet = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""
                raw_matched = m.group(0)[:80]

                # Redact prompt_injection payloads — they must not reach Claude's context
                if category == "prompt_injection":
                    snippet = "[REDACTED: prompt injection payload detected]"
                    matched = "[REDACTED]"
                else:
                    snippet = raw_snippet
                    matched = raw_matched

                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "category": category,
                    "severity": severity,
                    "description": description,
                    "matched": matched,
                    "snippet": snippet,
                    "false_positive_note": fp_note,
                })
        except re.error:
            pass
    return findings


def build_report(source, scanned_files, all_findings, skill_metadata=None):
    """Build the final JSON report from findings."""
    all_findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["file"], f["line"])
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    score = round(min(10.0, (
        counts["critical"] * 3.0 +
        counts["high"] * 1.5 +
        counts["medium"] * 0.5 +
        counts["low"] * 0.1
    )), 1)

    if score >= 8:
        classification = "CRITICAL"
    elif score >= 6:
        classification = "HIGH"
    elif score >= 3:
        classification = "MEDIUM"
    elif score >= 1:
        classification = "LOW"
    else:
        classification = "CLEAN"

    report = {
        "source": source,
        "scanned_files": scanned_files,
        "finding_count": len(all_findings),
        "counts_by_severity": counts,
        "risk_score": score,
        "risk_classification": classification,
        "findings": all_findings,
    }

    if skill_metadata:
        # Sanitize description: truncate and redact if it triggers any prompt_injection rule
        description = str(skill_metadata.get("description", ""))[:300]
        for category, _, pattern, _, _ in RULES:
            if category == "prompt_injection" and re.search(pattern, description, re.IGNORECASE):
                description = "[REDACTED: suspicious content in description field]"
                break

        report["skill_metadata"] = {
            "name": str(skill_metadata.get("name", "")),
            "description": description,
            "allowed_tools": skill_metadata.get("allowed-tools", []),
        }

    return report


def scan_directory(skill_dir):
    """Scan a local skill directory. Never exposes raw file content to caller."""
    all_findings = []
    scanned_files = []
    skill_metadata = None
    skill_dir_abs = os.path.abspath(skill_dir)

    for root, dirs, files in os.walk(skill_dir_abs):
        dirs[:] = [
            d for d in dirs
            if not d.startswith('.') and d not in ('__pycache__', 'node_modules', '.git')
        ]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCANNABLE_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, skill_dir_abs)
            scanned_files.append(rel_path)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                # Extract frontmatter from top-level SKILL.md only
                if fname.upper() == 'SKILL.MD' and os.path.abspath(root) == skill_dir_abs:
                    skill_metadata = extract_frontmatter(content)
                findings = scan_file(rel_path, content)
                all_findings.extend(findings)
            except Exception as e:
                all_findings.append({
                    "file": rel_path, "line": 0, "category": "scan_error",
                    "severity": "low", "description": f"Could not read file: {e}",
                    "matched": "", "snippet": "", "false_positive_note": "",
                })

    return build_report(skill_dir, scanned_files, all_findings, skill_metadata)


# ---- GitHub URL support ----

def parse_github_url(url):
    """
    Parse a GitHub URL and return (owner, repo, ref, subpath).
    Supports:
      https://github.com/owner/repo
      https://github.com/owner/repo/tree/main
      https://github.com/owner/repo/tree/main/subdir/path
    """
    m = re.match(
        r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/([^/]+)(/.*)?)?$',
        url.rstrip('/')
    )
    if not m:
        return None
    owner = m.group(1)
    repo = m.group(2)
    ref = m.group(3) or 'HEAD'
    subpath = (m.group(4) or '').strip('/')
    return owner, repo, ref, subpath


def github_api_get(url, token=None):
    req = urllib.request.Request(url)
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('User-Agent', 'skill-audit/1.0')
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode('utf-8'))


def fetch_repo_trust(owner, repo, token=None):
    """
    Fetch repository and owner stats from the GitHub API and compute a trust score.

    Trust score (0–100) is based on:
      - Stars: community adoption signal
      - Owner type (Organization vs User): accountability signal
      - Owner followers: author reputation signal
      - Repo age: longevity signal
      - License presence: transparency signal
      - Forks: active usage signal

    Classifications:
      VERIFIED    (70–100): Established, widely-used
      ESTABLISHED (40–69):  Reputable with meaningful history
      EMERGING    (20–39):  Newer or smaller project
      UNKNOWN     (5–19):   Limited history or adoption
      SUSPICIOUS  (0–4):    New account, zero community presence

    Never raises — returns error info on failure.
    """
    trust = {
        "owner": owner,
        "repo": repo,
        "stars": None,
        "forks": None,
        "owner_type": None,
        "owner_followers": None,
        "repo_age_days": None,
        "last_updated_days": None,
        "has_license": None,
        "license_name": None,
        "trust_score": 0,
        "trust_classification": "UNKNOWN",
        "trust_signals": [],
        "error": None,
    }

    # Fetch repo info
    try:
        repo_data = github_api_get(
            f"https://api.github.com/repos/{owner}/{repo}", token
        )
        trust["stars"] = repo_data.get("stargazers_count", 0)
        trust["forks"] = repo_data.get("forks_count", 0)
        trust["owner_type"] = repo_data.get("owner", {}).get("type", "User")

        now = datetime.now(timezone.utc)
        created_at = repo_data.get("created_at")
        pushed_at = repo_data.get("pushed_at") or repo_data.get("updated_at")
        if created_at:
            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            trust["repo_age_days"] = (now - created).days
        if pushed_at:
            pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            trust["last_updated_days"] = (now - pushed).days

        license_info = repo_data.get("license")
        trust["has_license"] = license_info is not None
        trust["license_name"] = license_info.get("name") if license_info else None
    except Exception as e:
        trust["error"] = f"Could not fetch repo info: {e}"
        return trust

    # Fetch owner info (non-fatal)
    try:
        owner_data = github_api_get(
            f"https://api.github.com/users/{owner}", token
        )
        trust["owner_followers"] = owner_data.get("followers", 0)
    except Exception:
        trust["owner_followers"] = 0

    # Compute trust score
    score = 0
    signals = []

    stars = trust["stars"] or 0
    if stars >= 1000:
        score += 40
        signals.append(f"+40 pts: {stars:,} stars (well-known)")
    elif stars >= 100:
        score += 25
        signals.append(f"+25 pts: {stars:,} stars (established)")
    elif stars >= 10:
        score += 10
        signals.append(f"+10 pts: {stars:,} stars (gaining traction)")
    elif stars >= 1:
        score += 5
        signals.append(f"+5 pts: {stars} stars")
    else:
        signals.append("0 pts: no stars yet")

    if trust["owner_type"] == "Organization":
        score += 20
        signals.append(f"+20 pts: owner is an Organization ({owner})")

    followers = trust["owner_followers"] or 0
    if followers >= 1000:
        score += 20
        signals.append(f"+20 pts: owner has {followers:,} followers")
    elif followers >= 100:
        score += 15
        signals.append(f"+15 pts: owner has {followers:,} followers")
    elif followers >= 10:
        score += 5
        signals.append(f"+5 pts: owner has {followers} followers")
    else:
        signals.append(f"0 pts: owner has {followers} followers (new or low-profile account)")

    age = trust["repo_age_days"]
    if age is not None:
        if age >= 365:
            score += 20
            signals.append(f"+20 pts: repo is {age} days old (1+ year)")
        elif age >= 180:
            score += 15
            signals.append(f"+15 pts: repo is {age} days old (6+ months)")
        elif age >= 30:
            score += 10
            signals.append(f"+10 pts: repo is {age} days old (1+ month)")
        elif age >= 7:
            score += 5
            signals.append(f"+5 pts: repo is {age} days old (1+ week)")
        else:
            signals.append(f"WARNING: repo is only {age} days old — very new")

    if trust["has_license"]:
        score += 5
        signals.append(f"+5 pts: has license ({trust['license_name']})")
    else:
        signals.append("0 pts: no license declared")

    forks = trust["forks"] or 0
    if forks >= 10:
        score += 5
        signals.append(f"+5 pts: {forks} forks")
    elif forks >= 1:
        score += 2
        signals.append(f"+2 pts: {forks} fork(s)")

    trust["trust_score"] = min(100, score)
    trust["trust_signals"] = signals

    if trust["trust_score"] >= 70:
        trust["trust_classification"] = "VERIFIED"
    elif trust["trust_score"] >= 40:
        trust["trust_classification"] = "ESTABLISHED"
    elif trust["trust_score"] >= 20:
        trust["trust_classification"] = "EMERGING"
    elif trust["trust_score"] >= 5:
        trust["trust_classification"] = "UNKNOWN"
    else:
        trust["trust_classification"] = "SUSPICIOUS"

    return trust


def scan_github_url(url):
    """
    Scan a GitHub repository or subdirectory for malicious patterns.
    Enforces MAX_GITHUB_FILES and MAX_GITHUB_BYTES limits.
    Never writes to disk.
    """
    token = os.environ.get('GITHUB_TOKEN')
    parsed = parse_github_url(url)
    if not parsed:
        return {"error": f"Cannot parse GitHub URL: {url}", "source": url,
                "risk_score": 0, "risk_classification": "ERROR",
                "finding_count": 0, "counts_by_severity": {}, "findings": []}

    owner, repo, ref, subpath = parsed

    # Fetch repository trust signals (stars, age, owner reputation, etc.)
    repo_trust = fetch_repo_trust(owner, repo, token)

    # Use recursive git tree API for efficient file listing
    trees_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
    try:
        tree_data = github_api_get(trees_url, token)
    except urllib.error.HTTPError as e:
        return {"error": f"GitHub API HTTP {e.code}: {e.reason}", "source": url,
                "risk_score": 0, "risk_classification": "ERROR",
                "finding_count": 0, "counts_by_severity": {}, "findings": []}
    except Exception as e:
        return {"error": f"GitHub API error: {e}", "source": url,
                "risk_score": 0, "risk_classification": "ERROR",
                "finding_count": 0, "counts_by_severity": {}, "findings": []}

    # Filter to scannable files within subpath
    all_blobs = [
        item for item in tree_data.get('tree', [])
        if item.get('type') == 'blob'
        and (not subpath
             or item['path'].startswith(subpath + '/')
             or item['path'] == subpath)
        and os.path.splitext(item['path'])[1].lower() in SCANNABLE_EXTENSIONS
    ]

    # Apply limits
    files_to_fetch = []
    total_bytes = 0
    for item in all_blobs:
        if len(files_to_fetch) >= MAX_GITHUB_FILES:
            break
        size = item.get('size', 0)
        if total_bytes + size > MAX_GITHUB_BYTES:
            break
        files_to_fetch.append(item)
        total_bytes += size

    all_findings = []
    scanned_files = []
    skill_metadata = None

    for item in files_to_fetch:
        file_path = item['path']
        rel_path = file_path[len(subpath):].lstrip('/') if subpath else file_path
        scanned_files.append(rel_path)

        contents_url = (
            f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={ref}"
        )
        try:
            file_data = github_api_get(contents_url, token)
            raw_bytes = base64.b64decode(file_data['content'].replace('\n', ''))
            content = raw_bytes.decode('utf-8', errors='replace')

            fname = os.path.basename(file_path)
            parent = os.path.dirname(file_path).rstrip('/')
            is_top_level_skill_md = (
                fname.upper() == 'SKILL.MD'
                and (not subpath or parent == subpath.rstrip('/'))
            )
            if is_top_level_skill_md:
                skill_metadata = extract_frontmatter(content)

            findings = scan_file(rel_path, content)
            all_findings.extend(findings)
        except Exception as e:
            all_findings.append({
                "file": rel_path, "line": 0, "category": "scan_error",
                "severity": "low", "description": f"Could not fetch file: {e}",
                "matched": "", "snippet": "", "false_positive_note": "",
            })

    report = build_report(url, scanned_files, all_findings, skill_metadata)
    report["repo_trust"] = repo_trust
    report["github_limits"] = {
        "max_files": MAX_GITHUB_FILES,
        "max_bytes": MAX_GITHUB_BYTES,
        "fetched_files": len(files_to_fetch),
        "fetched_bytes": total_bytes,
        "truncated": len(all_blobs) > len(files_to_fetch),
    }
    return report


# ---- Scan-all-skills mode ----

def scan_all_skills(cwd=None):
    """
    Scan every skill in .claude/skills/ and return a summary.
    Skips skill-audit itself: the auditor scanning its own documentation
    produces false positives because the reference files contain examples
    of the very patterns the scanner looks for.
    """
    if cwd is None:
        cwd = os.getcwd()

    skills_dir = os.path.join(cwd, '.claude', 'skills')
    if not os.path.isdir(skills_dir):
        return {
            "error": f"No skills directory found at {skills_dir}",
            "source": skills_dir,
        }

    skill_names = sorted(
        d for d in os.listdir(skills_dir)
        if os.path.isdir(os.path.join(skills_dir, d))
        and not d.startswith('.')
        and d != 'skill-audit'  # skip self: reference docs contain example patterns
    )
    if not skill_names:
        return {"error": "No skills found", "source": skills_dir}

    results = []
    for name in skill_names:
        path = os.path.join(skills_dir, name)
        report = scan_directory(path)
        results.append({
            "skill": name,
            "risk_score": report["risk_score"],
            "risk_classification": report["risk_classification"],
            "finding_count": report["finding_count"],
            "counts_by_severity": report["counts_by_severity"],
            "skill_metadata": report.get("skill_metadata", {}),
            "detail": report,
        })

    overall_max = max((r["risk_score"] for r in results), default=0)
    return {
        "source": skills_dir,
        "skills_scanned": len(results),
        "overall_max_risk_score": overall_max,
        "results": results,
    }


# ---- Entry point ----

def main():
    if len(sys.argv) < 2:
        report = scan_all_skills()
    elif sys.argv[1].startswith(('http://', 'https://')):
        report = scan_github_url(sys.argv[1])
    else:
        skill_dir = sys.argv[1]
        if not os.path.isdir(skill_dir):
            print(json.dumps({"error": f"Not a directory: {skill_dir}"}))
            sys.exit(1)
        report = scan_directory(skill_dir)

    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
