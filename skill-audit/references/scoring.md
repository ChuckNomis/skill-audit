# Risk Scoring Reference & Report Template

---

## Scoring Formula

```
raw_score = (critical_count × 3.0) + (high_count × 1.5) + (medium_count × 0.5) + (low_count × 0.1)
risk_score = min(10.0, raw_score)   # capped at 10
```

This formula is implemented in `scanner.py` and is already computed in the JSON output.
The `risk_score` and `risk_classification` fields are ready to use directly.

---

## Classification Thresholds

| Score | Classification | Meaning |
|---|---|---|
| 0 | CLEAN | No issues found |
| 0.1 – 2.9 | LOW | Minor concerns; review before installing |
| 3.0 – 5.9 | MEDIUM | Suspicious patterns; careful review required |
| 6.0 – 7.9 | HIGH | Significant risk; do not install without explicit remediation |
| 8.0 – 10.0 | CRITICAL | Quarantine immediately; do not install |

---

## Recommended Actions by Classification

| Classification | Action |
|---|---|
| CLEAN | Safe to install |
| LOW | Install with awareness of flagged items; review false positive notes |
| MEDIUM | Do not install without reviewing all flagged lines in the source |
| HIGH | Do not install; contact skill author for clarification or find alternative |
| CRITICAL | Do not install; quarantine the skill directory; report to source |

---

## Contextual Score Adjustment

After computing the scanner's raw score, apply context-based adjustments from `patterns.md`.
Adjustments are bounded: the final score cannot go below 0 or above 10.

Example: scanner reports score 4.5 (MEDIUM) for an AWS skill with `.aws/credentials`
reference. Apply -1.0 contextual adjustment → final score 3.5 (still MEDIUM, but lower).
Document the adjustment in the report.

---

## Repository Trust Score (GitHub scans only)

When `repo_trust` is present in the scanner JSON, include it in the report.

### Trust Score (0–100)

| Score | Classification | Meaning |
|---|---|---|
| 70–100 | VERIFIED | Established, widely-used project |
| 40–69 | ESTABLISHED | Reputable source with meaningful history |
| 20–39 | EMERGING | Newer or smaller project |
| 5–19 | UNKNOWN | Limited history or adoption |
| 0–4 | SUSPICIOUS | Very new account, no community presence |

### Signals used (additive)

| Signal | Points |
|---|---|
| Stars ≥ 1,000 | +40 |
| Stars ≥ 100 | +25 |
| Stars ≥ 10 | +10 |
| Stars ≥ 1 | +5 |
| Owner is Organization | +20 |
| Owner followers ≥ 1,000 | +20 |
| Owner followers ≥ 100 | +15 |
| Owner followers ≥ 10 | +5 |
| Repo age ≥ 1 year | +20 |
| Repo age ≥ 6 months | +15 |
| Repo age ≥ 1 month | +10 |
| Repo age ≥ 1 week | +5 |
| Has license | +5 |
| Forks ≥ 10 | +5 |
| Forks ≥ 1 | +2 |

### Combined interpretation

A SUSPICIOUS trust score does NOT make a skill malicious — it just means there is no
community evidence of legitimacy. Combine with the security risk score:

| Risk | Trust | Verdict |
|---|---|---|
| CLEAN | VERIFIED | Safe to install |
| CLEAN | SUSPICIOUS | Use with caution — unproven source |
| HIGH | VERIFIED | Genuine security issue even in trusted repos |
| HIGH | SUSPICIOUS | Do not install |
| CRITICAL | any | Do not install |

---

## Report Template

Use this template to format the final security report. Fill in values from the scanner JSON.

---

```markdown
# Skill Security Audit Report

**Target**: {source}
**Scanned**: {scanned_file_count} files
**Risk Score**: {risk_score}/10 — {risk_classification}
**Trust Score**: {repo_trust.trust_score}/100 — {repo_trust.trust_classification}  ← GitHub only

{classification_banner}

---

## Source Reputation  ← include only for GitHub scans

| Field | Value |
|---|---|
| Repository | {owner}/{repo} |
| Stars | {repo_trust.stars} |
| Forks | {repo_trust.forks} |
| Owner type | {repo_trust.owner_type} |
| Owner followers | {repo_trust.owner_followers} |
| Repo age | {repo_trust.repo_age_days} days |
| Last updated | {repo_trust.last_updated_days} days ago |
| License | {repo_trust.license_name or "none"} |
| Trust score | {repo_trust.trust_score}/100 ({repo_trust.trust_classification}) |

**Trust signals:**
{for each signal in repo_trust.trust_signals: "- {signal}"}

---

## Skill Identity

| Field | Value |
|---|---|
| Name | {skill_metadata.name or "not found"} |
| Description | {skill_metadata.description or "not found"} |
| Allowed Tools | {skill_metadata.allowed_tools joined with ", " or "none declared"} |

---

## Summary of Findings

| Severity | Count |
|---|---|
| Critical | {counts.critical} |
| High | {counts.high} |
| Medium | {counts.medium} |
| Low | {counts.low} |
| **Total** | {finding_count} |

---

## Findings

{for each finding, sorted by severity:}

### [{severity_badge}] {description}
- **File**: `{file}` line {line}
- **Category**: {category}
- **Matched**: `{matched}`
- **Snippet**: `{snippet}`
- **False positive note**: {false_positive_note}
- **Recommendation**: {recommendation from table below}

---

## Recommendation

{final_recommendation}

{if truncated (GitHub scan):}
> Note: Scan was limited to {fetched_files} files ({fetched_bytes} bytes).
> The repository may contain additional files not scanned.
> Set GITHUB_TOKEN environment variable to increase API rate limits.
```

---

## Classification Banners

Use one of these banners based on `risk_classification`:

**CLEAN**:
```
No security issues detected. Safe to install.
```

**LOW**:
```
Minor concerns detected. Review flagged items before installing.
```

**MEDIUM**:
```
Suspicious patterns found. Manual review of flagged lines required before installing.
```

**HIGH**:
```
Significant security risks detected. Do NOT install without explicit remediation.
Contact the skill author or find an alternative.
```

**CRITICAL**:
```
CRITICAL SECURITY RISK. Do NOT install this skill.
Quarantine the skill directory immediately and do not execute any of its scripts.
```

---

## Per-Severity Recommendations

Use these per-finding when generating the Findings section:

| Category | Severity | Recommendation |
|---|---|---|
| `prompt_injection` | critical | Remove the skill immediately; payload redacted for safety |
| `prompt_injection` | high | Review the flagged line; likely malicious intent |
| `credential_access` | critical | Verify whether this access is disclosed and user-initiated |
| `credential_access` | high | Check if the credential is transmitted externally |
| `exfiltration` | critical | Identify the target URL; if hardcoded and unknown, discard skill |
| `exfiltration` | high | Review data being transmitted and to where |
| `hooks_autoexec` | critical | Skills must not register hooks; discard skill |
| `hooks_autoexec` | high | Verify user is always prompted before any automatic execution |
| `settings_modification` | critical | Skills must not modify settings.json; discard skill |
| `settings_modification` | high | Confirm CLAUDE.md modification is user-requested |
| `obfuscation` | high | Decode and inspect the obfuscated content before trusting the skill |
| `excessive_permissions` | critical | Bash(*) must be explicitly justified by skill purpose |
| `excessive_permissions` | medium | Verify Write access is necessary for stated purpose |
| `deception` | critical | Discard skill; deception of users is never acceptable |
| `deception` | high | Review full context of flagged line |
