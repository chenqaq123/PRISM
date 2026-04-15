#!/usr/bin/env python3
"""Quick evaluation runner for NEXUS across the test-skills directory."""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from nexus.scanner import scan_skill
from nexus.models import Verdict

# Ground truth labels: True = malicious, False = benign
GROUND_TRUTH = {
    # True Positives (malicious)
    "av1-obfuscation":           True,
    "av2-nl-injection":          True,
    "av3-semantic-camouflage":   True,
    "av4-reverse-camouflage":    True,
    "av7-timebomb":              True,
    "av8-supply-chain":          True,
    "env-exfil":                 True,
    "persistence-install":       True,
    "credential-encode-exfil":   True,
    "capability-inflation":      True,
    "evil-formatter":            True,
    "cross-script-exfil":        True,
    "phantom-backdoor":          True,
    # ── Batch 2: new attack patterns ──
    "js-exfil":                  True,   # JS env var exfil via https.request
    "shell-credential-harvest":  True,   # Shell: cat ~/.ssh/id_rsa | curl
    "av5-prompt-injection":      True,   # SKILL.md prompt injection (code is clean)
    "dns-exfil":                 True,   # DNS-based data exfiltration
    "reverse-shell":             True,   # Socket reverse shell + os.dup2
    "mixed-hidden-exfil":        True,   # 95% benign code + hidden telemetry exfil
    "polyglot-attack":           True,   # Python orchestrator + JS credential stealer
    # True Negatives (benign)
    "benign-formatter":          False,
    "benign-git-tool":           False,
    "benign-api-caller":         False,
    "benign-security-auditor":   False,
    "benign-deploy-helper":      False,
    "benign-multifile":          False,
    # ── Batch 2: new benign patterns ──
    "benign-test-runner":        False,  # Many subprocess calls (pytest/jest)
    "benign-webhook-notifier":   False,  # Legitimate HTTP POST to webhook
    # Edge cases — benign but with legitimate security-adjacent operations
    "edge-ssh-keygen":           False,
    "edge-env-manager":          False,
    "edge-declared-analytics":   False,
    "edge-credential-rotator":   False,  # Touches ~/.ssh but never exfiltrates
}

# Verdicts we treat as "flagged" (malicious prediction)
FLAGGED_VERDICTS = {Verdict.BLOCK, Verdict.REVIEW}

def run():
    base = Path(__file__).parent / "test-skills"
    results = []

    for name, is_malicious in sorted(GROUND_TRUTH.items()):
        skill_dir = base / name
        if not skill_dir.exists():
            print(f"  [SKIP] {name} — directory not found")
            continue
        try:
            report = scan_skill(str(skill_dir), use_llm=False, quiet=True)
            flagged = report.verdict in FLAGGED_VERDICTS
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            flagged = False

        tp = is_malicious and flagged
        tn = not is_malicious and not flagged
        fp = not is_malicious and flagged
        fn = is_malicious and not flagged

        status = ("TP" if tp else "TN" if tn else "FP" if fp else "FN")
        label  = "MAL" if is_malicious else "BEN"
        pred   = report.verdict.value
        score  = report.overall_score

        results.append((name, label, pred, score, status))
        mark = "✓" if status in ("TP", "TN") else "✗"
        print(f"  {mark} {name:<32} [{label}] → {pred:<8} (score={score:.3f})  [{status}]")

    # Aggregate
    tp = sum(1 for *_, s in results if s == "TP")
    tn = sum(1 for *_, s in results if s == "TN")
    fp = sum(1 for *_, s in results if s == "FP")
    fn = sum(1 for *_, s in results if s == "FN")
    total = len(results)

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)
    fpr       = fp / max(fp + tn, 1)
    acc       = (tp + tn) / max(total, 1)

    print()
    print("=" * 60)
    print(f"  Total evaluated : {total}")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"  Precision : {precision:.3f}")
    print(f"  Recall    : {recall:.3f}")
    print(f"  F1        : {f1:.3f}")
    print(f"  FPR       : {fpr:.3f}  ({fp}/{fp+tn})")
    print(f"  Accuracy  : {acc:.3f}")
    print("=" * 60)

    # Print FP details
    if fp:
        print("\nFalse Positives (benign flagged as malicious):")
        for name, label, pred, score, s in results:
            if s == "FP":
                print(f"  → {name}  verdict={pred}  score={score:.3f}")

    # Print FN details
    if fn:
        print("\nFalse Negatives (malicious missed):")
        for name, label, pred, score, s in results:
            if s == "FN":
                print(f"  → {name}  verdict={pred}  score={score:.3f}")

if __name__ == "__main__":
    run()
