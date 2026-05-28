#!/usr/bin/env python3
"""
zsh-smart-cleaner — Smart ZSH history cleaner.

Features: burst deduplication, pattern filtering, malformed detection,
env prefix removal, security scanning, date-range removal, and analysis.

Usage:
  python3 zsh_smart_cleaner.py [history_file] [options]
"""

import argparse
import json
import os
import re
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone

# ─── Defaults ───────────────────────────────────────────────────────────────

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.zsh_smart_cleaner.json")

ZSH_ENTRY_RE = re.compile(r"^:\s*\d+:\d+;")

ENV_ASSIGN_RE = re.compile(r"^[A-Z_][A-Z0-9_]*=")
HEX_TOKEN_RE = re.compile(r"[0-9a-fA-F]{20,}")
BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")

DEFAULT_IGNORE_LIST = []

DEFAULT_ALLOW_LIST = []

REPETITIVE_PATTERNS = [
    re.compile(r"^(\\|/)\s*$"),
    re.compile(r"^echo\s+['\"]?\s*['\"]?$"),
]

DEFAULT_MAX_LENGTH = 500
DEFAULT_BACKUP_RETENTION = 10
DEFAULT_MAX_BURST = 2


# ─── Config ─────────────────────────────────────────────────────────────────

def load_config(config_path=None):
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return json.load(f)

    return {
        "ignore_list": DEFAULT_IGNORE_LIST,
        "allow_list": DEFAULT_ALLOW_LIST,
        "defaults": {
            "max_length": DEFAULT_MAX_LENGTH,
            "backup_retention": DEFAULT_BACKUP_RETENTION,
            "max_burst": DEFAULT_MAX_BURST,
        },
    }


# ─── Rule Matching ──────────────────────────────────────────────────────────

def compile_rule(rule):
    pattern = rule["pattern"]
    match_type = rule.get("match_type", "contains")
    desc = rule.get("description", "")

    if match_type == "exact":
        return lambda cmd, p=pattern: cmd == p, desc
    elif match_type == "contains":
        return lambda cmd, p=pattern: p in cmd, desc
    elif match_type == "starts_with":
        return lambda cmd, p=pattern: cmd.startswith(p), desc
    elif match_type == "ends_with":
        return lambda cmd, p=pattern: cmd.endswith(p), desc
    elif match_type == "regex":
        compiled = re.compile(pattern, re.IGNORECASE)
        return lambda cmd, c=compiled: c.search(cmd) is not None, desc
    else:
        raise ValueError(f"Unknown match_type: {match_type}")


def matches_any(command, rules):
    for matcher, desc in rules:
        if matcher(command):
            return True, desc
    return False, ""


# ─── Malformed Detection ────────────────────────────────────────────────────

def detect_malformed(command):
    reasons = []

    if command.count('"') % 2 != 0:
        reasons.append("unclosed double quote")
    if command.count("'") % 2 != 0:
        reasons.append("unclosed single quote")
    if command.count("`") % 2 != 0:
        reasons.append("unclosed backtick")
    if command.count("(") != command.count(")"):
        reasons.append("unmatched parentheses")

    unfinished = re.findall(r'\$\{[^}]*$', command)
    if unfinished:
        reasons.append("unfinished variable substitution")

    return len(reasons) > 0, reasons


# ─── Pattern Garbage Detection ──────────────────────────────────────────────

def is_pattern_garbage(command):
    return any(p.search(command) for p in REPETITIVE_PATTERNS)


# ─── Pure Env Prefix Detection ──────────────────────────────────────────────

def is_pure_env_prefix(command):
    """Detect commands that are ONLY env var assignments with no actual command.

    Matches: ENV=production PROFILE=tgo-$ENV SERVICE=backend
    Keeps:   DEBUG=1 python app.py   (python is not an env assignment)
    Keeps:   ANTHROPIC_API_KEY=sk-xxx claude  (claude is not an env assignment)
    """
    tokens = command.split()
    if not tokens:
        return False
    return all(ENV_ASSIGN_RE.match(t) for t in tokens)


# ─── History Parsing ────────────────────────────────────────────────────────

def parse_zsh_history(content):
    """Parse ZSH extended history format with multiline support.

    ZSH extended format:
      : <timestamp>:<duration>;<command>

    Multiline commands are stored with literal backslash-newline:
      : 1234567890:0;echo hello \
      world

    The parser joins continuation lines only when the next line does NOT
    start a new history entry (checked against ZSH_ENTRY_RE).
    """
    entries = []
    orphan_lines = 0
    total_lines = 0
    lines = content.split("\n")
    # Trailing newline produces an empty string at the end; skip it
    if lines and lines[-1] == "":
        lines = lines[:-1]
    i = 0

    while i < len(lines):
        total_lines += 1
        line = lines[i]

        if not line or line.startswith("#"):
            orphan_lines += 1
            i += 1
            continue

        match = re.match(r"^:\s*(\d+):(\d+);(.*)$", line, re.DOTALL)
        if match:
            timestamp = int(match.group(1))
            duration = int(match.group(2))
            command = match.group(3)

            while command.endswith("\\") and i + 1 < len(lines):
                next_line = lines[i + 1]
                if ZSH_ENTRY_RE.match(next_line):
                    break
                i += 1
                total_lines += 1
                command = command[:-1] + "\n" + next_line

            entries.append({
                "timestamp": timestamp,
                "duration": duration,
                "command": command,
                "source_line": total_lines,
            })
        else:
            orphan_lines += 1

        i += 1

    return entries, orphan_lines, total_lines


def serialize_entries(entries):
    if not entries:
        return ""
    parts = []
    for e in entries:
        cmd = e["command"].replace("\n", "\\\n")
        parts.append(f": {e['timestamp']}:{e['duration']};{cmd}")
    return "\n".join(parts) + "\n"


# ─── Core Cleaning Logic ────────────────────────────────────────────────────

def clean_history(entries, config, max_length, max_burst=2, keep_duplicates=False, verbose=False):
    allow_rules = [compile_rule(r) for r in config.get("allow_list", [])]
    ignore_rules = [compile_rule(r) for r in config.get("ignore_list", [])]

    removed = {
        "empty": 0,
        "allow_rule": 0,
        "allow_rule_details": [],
        "malformed": 0,
        "pattern_garbage": 0,
        "env_prefix": 0,
        "too_long": 0,
        "burst_duplicate": 0,
        "duplicate": 0,
    }

    seen = set()
    kept = []

    prev_normalized = None
    burst_count = 0

    for entry in reversed(entries):
        cmd = entry["command"].strip()

        if not cmd:
            removed["empty"] += 1
            prev_normalized = None
            burst_count = 0
            continue

        normalized = normalize_command(cmd)

        if normalized == prev_normalized and normalized:
            burst_count += 1
        else:
            burst_count = 1
        prev_normalized = normalized

        matched, desc = matches_any(cmd, allow_rules)
        if matched:
            removed["allow_rule"] += 1
            removed["allow_rule_details"].append((cmd[:80], desc))
            continue

        is_malformed, reasons = detect_malformed(cmd)
        if is_malformed:
            removed["malformed"] += 1
            if verbose:
                print(f"  [malformed] line {entry['source_line']}: {', '.join(reasons)} — {cmd[:60]}")
            continue

        if is_pattern_garbage(cmd):
            removed["pattern_garbage"] += 1
            if verbose:
                print(f"  [pattern]   line {entry['source_line']}: {cmd[:60]}")
            continue

        if is_pure_env_prefix(cmd):
            removed["env_prefix"] += 1
            if verbose:
                print(f"  [env_prefix] line {entry['source_line']}: {cmd[:60]}")
            continue

        # Burst check applies to ALL entries that pass the above filters,
        # including those matching ignore rules. Keeps the newest N.
        if not keep_duplicates and max_burst > 0 and burst_count > max_burst:
            removed["burst_duplicate"] += 1
            continue

        matched, desc = matches_any(cmd, ignore_rules)
        if matched:
            kept.append(entry)
            continue

        if max_length > 0 and len(cmd) > max_length:
            removed["too_long"] += 1
            if verbose:
                print(f"  [too_long]  line {entry['source_line']}: {cmd[:60]}...")
            continue

        if not keep_duplicates:
            # Global dedup only applies to first-in-group or when burst is disabled
            if burst_count == 1 or max_burst == 0:
                if normalized in seen:
                    removed["duplicate"] += 1
                    continue
            seen.add(normalized)

        kept.append(entry)

    kept.reverse()
    return kept, removed


def normalize_command(cmd):
    """Normalize for dedup: strip trailing whitespace, collapse multiple spaces."""
    return re.sub(r"\s+", " ", cmd.strip())


# ─── Date-Range Removal ─────────────────────────────────────────────────────

def remove_between_dates(entries, start_date, end_date):
    removed = 0
    kept = []
    for entry in entries:
        entry_date = datetime.fromtimestamp(entry["timestamp"], tz=timezone.utc).date()
        if start_date <= entry_date <= end_date:
            removed += 1
        else:
            kept.append(entry)
    return kept, removed


# ─── Analysis Mode ──────────────────────────────────────────────────────────

def analyze_history(entries, top_n=15):
    if not entries:
        print("No entries to analyze.")
        return

    print("=" * 60)
    print("ZSH History Analysis")
    print("=" * 60)
    print(f"Total entries: {len(entries)}")

    timestamps = [e["timestamp"] for e in entries]
    first = datetime.fromtimestamp(min(timestamps), tz=timezone.utc)
    last = datetime.fromtimestamp(max(timestamps), tz=timezone.utc)
    print(f"Date range: {first.strftime('%Y-%m-%d')} to {last.strftime('%Y-%m-%d')}")
    print(f"Span: {(last - first).days} days")

    cmd_counts = Counter()
    exe_counts = Counter()
    for e in entries:
        cmd = e["command"].strip()
        cmd_counts[cmd] += 1
        first_word = cmd.split()[0] if cmd.split() else ""
        exe_counts[first_word] += 1

    print(f"\nTop {top_n} most repeated commands:")
    print("-" * 60)
    for cmd, count in cmd_counts.most_common(top_n):
        display = cmd[:55] + "..." if len(cmd) > 55 else cmd
        print(f"  {count:>5}x  {display}")

    print(f"\nTop {top_n} executables:")
    print("-" * 60)
    for exe, count in exe_counts.most_common(top_n):
        print(f"  {count:>5}x  {exe}")

    dup_count = len(entries) - len(set(normalize_command(e["command"]) for e in entries))
    print(f"\nDuplicate entries: {dup_count} ({dup_count / len(entries) * 100:.1f}%)")

    avg_cmd_len = sum(len(e["command"]) for e in entries) / len(entries)
    print(f"Average command length: {avg_cmd_len:.0f} chars")

    print("=" * 60)


# ─── Security Scanner ───────────────────────────────────────────────────────

def scan_security(entries):
    """Scan history for real secrets (informational only, no auto-removal).

    Only flags actual token values (hex strings 20+ chars), not references
    to env vars or local file reads.
    """
    findings = {
        "auth_tokens": [],
        "csrf_tokens": [],
    }

    for entry in entries:
        cmd = entry["command"].strip()

        auth_match = re.search(r"Authorization:\s*Token\s+(\S+)", cmd)
        if auth_match:
            token = auth_match.group(1)
            if (HEX_TOKEN_RE.search(token) or BASE64_TOKEN_RE.search(token)) and not token.startswith("TokenTestTaker"):
                findings["auth_tokens"].append({
                    "line": entry["source_line"],
                    "command": cmd[:80] + "..." if len(cmd) > 80 else cmd,
                    "token_preview": token[:8] + "..." + token[-4:],
                })

        csrf_match = re.search(r"X-CSRFToken:\s*(\S+)", cmd)
        if csrf_match:
            token = csrf_match.group(1)
            if HEX_TOKEN_RE.search(token) or BASE64_TOKEN_RE.search(token):
                findings["csrf_tokens"].append({
                    "line": entry["source_line"],
                    "command": cmd[:80] + "..." if len(cmd) > 80 else cmd,
                    "token_preview": token[:8] + "..." + token[-4:],
                })

    return findings


def print_security_report(findings):
    print()
    print("=" * 60)
    print("Security Report")
    print("=" * 60)

    has_findings = False

    if findings["auth_tokens"]:
        has_findings = True
        print(f"\n  Auth tokens in commands: {len(findings['auth_tokens'])}")
        print("  These are real hex tokens in Authorization headers.")
        print("  If someone gets your history, they can replay these requests.")
        for f in findings["auth_tokens"][:5]:
            print(f"    line {f['line']}: {f['command'][:60]}")
            print(f"      token: {f['token_preview']}")
        if len(findings["auth_tokens"]) > 5:
            print(f"    ... and {len(findings['auth_tokens']) - 5} more")

    if findings["csrf_tokens"]:
        has_findings = True
        print(f"\n  CSRF tokens in commands: {len(findings['csrf_tokens'])}")
        print("  Real CSRF tokens stored in plaintext.")
        for f in findings["csrf_tokens"][:5]:
            print(f"    line {f['line']}: {f['command'][:60]}")
            print(f"      token: {f['token_preview']}")
        if len(findings["csrf_tokens"]) > 5:
            print(f"    ... and {len(findings['csrf_tokens']) - 5} more")

    if not has_findings:
        print("\n  No security issues found.")

    print("=" * 60)


# ─── Backup ─────────────────────────────────────────────────────────────────

def create_backup(filepath):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{filepath}.backup_{ts}"
    shutil.copy2(filepath, backup_path)
    return backup_path


def restore_backup(backup_path, filepath):
    shutil.copy2(backup_path, filepath)


def prune_backups(filepath, retention):
    dir_name = os.path.dirname(filepath) or "."
    base = os.path.basename(filepath)
    backups = sorted(
        [f for f in os.listdir(dir_name) if f.startswith(f"{base}.backup_")],
        reverse=True,
    )
    for old in backups[retention:]:
        os.remove(os.path.join(dir_name, old))


# ─── Prompt / Trust ─────────────────────────────────────────────────────────

def ask_for_confirmation():
    print("\nThis will modify your history file.")
    print("A backup will be created before any changes.")
    print()
    while True:
        choice = input("Proceed? [y/n/trust]: ").strip().lower()
        if choice in ("y", "yes"):
            return "continue"
        elif choice in ("n", "no"):
            return "cancel"
        elif choice == "trust":
            return "trust"
        print("Please enter y, n, or trust.")


# ─── JSON Report ────────────────────────────────────────────────────────────

def write_json_report(report_path, removed, stats):
    report = {
        "timestamp": datetime.now().isoformat(),
        "stats": stats,
        "removed": {k: v for k, v in removed.items() if k != "allow_rule_details"},
        "allow_rule_details": removed.get("allow_rule_details", []),
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Smart ZSH history cleaner — deduplicates, filters patterns, removes noise.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 zsh_smart_cleaner.py
  python3 zsh_smart_cleaner.py --dry-run --verbose
  python3 zsh_smart_cleaner.py --analyze
  python3 zsh_smart_cleaner.py --max-lines 5000
  python3 zsh_smart_cleaner.py --remove-between 2023-01-01 2024-01-01
  python3 zsh_smart_cleaner.py --yes --report-json report.json
  python3 zsh_smart_cleaner.py --security-report
        """,
    )
    parser.add_argument("history_file", nargs="?", default=None,
                        help="Path to ZSH history file (default: $HISTFILE or ~/.zsh_history)")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without modifying")
    parser.add_argument("--analyze", action="store_true", help="Show history statistics, no changes")
    parser.add_argument("--max-lines", type=int, help="Maximum number of entries to keep")
    parser.add_argument("--max-length", type=int, help="Maximum command length (chars)")
    parser.add_argument("--remove-between", nargs=2, metavar=("START", "END"),
                        help="Remove commands between two dates (YYYY-MM-DD)")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--verbose", action="store_true", help="Show removal details")
    parser.add_argument("--top-n", type=int, default=15, help="Top N for analysis (default: 15)")
    parser.add_argument("--no-backup", action="store_true", help="Skip backup (USE WITH CAUTION)")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--keep-duplicates", "-k", action="store_true",
                        help="Do not remove duplicate commands")
    parser.add_argument("--report-json", metavar="PATH",
                        help="Write machine-readable JSON report to PATH")
    parser.add_argument("--max-burst", type=int, default=None,
                        help="Max consecutive identical commands to keep (default: 2)")
    parser.add_argument("--no-burst-dedup", action="store_true",
                        help="Disable burst deduplication")
    parser.add_argument("--security-report", action="store_true",
                        help="Scan for real tokens/secrets in history (informational only)")

    args = parser.parse_args()

    if args.history_file:
        history_file = os.path.expanduser(args.history_file)
    else:
        histfile_env = os.environ.get("HISTFILE")
        history_file = os.path.expanduser(histfile_env if histfile_env else "~/.zsh_history")

    if not os.path.exists(history_file):
        print(f"Error: History file '{history_file}' not found.")
        sys.exit(1)

    config = load_config(args.config)
    defaults = config.get("defaults", {})
    max_length = args.max_length if args.max_length is not None else defaults.get("max_length", DEFAULT_MAX_LENGTH)
    backup_retention = defaults.get("backup_retention", DEFAULT_BACKUP_RETENTION)
    max_burst = args.max_burst if args.max_burst is not None else defaults.get("max_burst", DEFAULT_MAX_BURST)
    if args.no_burst_dedup:
        max_burst = 0

    with open(history_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    entries, orphan_lines, total_lines = parse_zsh_history(content)

    if args.analyze:
        analyze_history(entries, top_n=args.top_n)
        return

    if args.security_report:
        findings = scan_security(entries)
        print_security_report(findings)
        return

    if not entries:
        print("No valid history entries found.")
        return

    print(f"Loaded {len(entries)} entries from {history_file}")
    print(f"Orphan lines: {orphan_lines}")
    if max_burst > 0:
        print(f"Burst dedup: max {max_burst} consecutive identical commands")

    if args.remove_between:
        from datetime import date as date_type
        try:
            start = date_type.fromisoformat(args.remove_between[0])
            end = date_type.fromisoformat(args.remove_between[1])
        except ValueError:
            print("Error: Dates must be in YYYY-MM-DD format.")
            sys.exit(1)
        if start > end:
            print("Error: Start date must be before or equal to end date.")
            sys.exit(1)
        entries, date_removed = remove_between_dates(entries, start, end)
        print(f"Date range removal: {date_removed} entries removed ({start} to {end})")

    if not args.dry_run and not args.yes:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("Error: Non-interactive mode requires --yes to modify history. Use --dry-run for preview.")
            sys.exit(2)
        decision = ask_for_confirmation()
        if decision == "cancel":
            print("Operation canceled by user.")
            sys.exit(2)
        if decision == "trust":
            print("Trust saved for this session.")

    kept, removed = clean_history(
        entries, config, max_length,
        max_burst=max_burst,
        keep_duplicates=args.keep_duplicates,
        verbose=args.verbose,
    )

    max_lines_truncated = 0
    if args.max_lines and len(kept) > args.max_lines:
        max_lines_truncated = len(kept) - args.max_lines
        kept = kept[-args.max_lines:]

    total_removed = sum(v for k, v in removed.items() if isinstance(v, int)) + max_lines_truncated

    print(f"\n{'=' * 60}")
    print(f"Cleaning Summary")
    print(f"{'=' * 60}")
    print(f"  Original entries:       {len(entries)}")
    print(f"  Entries after cleaning: {len(kept)}")
    print(f"  Total removed:          {total_removed}")
    print(f"  Reduction:              {total_removed / len(entries) * 100:.1f}%")
    print(f"\n  Removal breakdown:")
    print(f"    Empty lines:          {removed['empty']}")
    print(f"    Orphan lines:         {orphan_lines}")
    print(f"    Allow-list matches:   {removed['allow_rule']}")
    print(f"    Malformed commands:   {removed['malformed']}")
    print(f"    Pattern garbage:      {removed['pattern_garbage']}")
    print(f"    Env prefix commands:  {removed['env_prefix']}")
    print(f"    Too long commands:    {removed['too_long']}")
    print(f"    Burst duplicates:     {removed['burst_duplicate']}")
    print(f"    Duplicates:           {removed['duplicate']}")
    if max_lines_truncated:
        print(f"    Max-lines truncated:  {max_lines_truncated}")

    if removed["allow_rule_details"] and args.verbose:
        print(f"\n  Allow-list removals:")
        for cmd, desc in removed["allow_rule_details"][:20]:
            print(f"    [{desc}] {cmd}")
        if len(removed["allow_rule_details"]) > 20:
            print(f"    ... and {len(removed['allow_rule_details']) - 20} more")

    if args.dry_run:
        print(f"\nDRY RUN: No files were modified.")
        print(f"Reload zsh history with: fc -R")
        if args.report_json:
            stats = {
                "original_entries": len(entries),
                "final_entries": len(kept),
                "total_removed": total_removed,
                "dry_run": True,
            }
            write_json_report(os.path.expanduser(args.report_json), removed, stats)
            print(f"JSON report written to: {os.path.expanduser(args.report_json)}")
        return

    backup_path = None
    if not args.no_backup:
        backup_path = create_backup(history_file)
        print(f"\nBackup created: {backup_path}")

    try:
        new_content = serialize_entries(kept)
        with open(history_file, "w", encoding="utf-8") as f:
            f.write(new_content)
    except Exception as e:
        if backup_path:
            print(f"\nWrite failed: {e}")
            print("Restoring from backup...")
            restore_backup(backup_path, history_file)
            print("Backup restored successfully.")
            sys.exit(1)
        raise

    if not args.no_backup:
        prune_backups(history_file, backup_retention)

    print(f"\nHistory cleaning complete.")
    print(f"Reload zsh history with: fc -R")

    if args.report_json:
        stats = {
            "original_entries": len(entries),
            "final_entries": len(kept),
            "total_removed": total_removed,
            "backup_path": backup_path,
            "dry_run": False,
        }
        write_json_report(os.path.expanduser(args.report_json), removed, stats)
        print(f"JSON report written to: {os.path.expanduser(args.report_json)}")


if __name__ == "__main__":
    main()
