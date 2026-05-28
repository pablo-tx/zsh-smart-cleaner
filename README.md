# zsh-smart-cleaner

Smart ZSH history cleaner — a single, zero-dependency Python script.

## Features

- **Burst deduplication** — Removes consecutive duplicate commands, keeping the newest N (default: 2)
- **Pattern-based filtering** — Configurable allow/ignore lists with regex, exact, starts_with, and contains matching
- **Malformed command detection** — Finds unclosed quotes, unmatched parentheses, and unfinished variable substitutions
- **Environment prefix detection** — Removes pure env var exports (`ENV=production SERVICE=backend`) while keeping commands with env prefixes (`DEBUG=1 python app.py`)
- **Security scanning** — Detects real auth tokens and CSRF secrets in your history (informational only, never auto-removes)
- **Date-range removal** — Delete all commands between two dates
- **History analysis** — Top commands, top executables, duplicate count, date range, average command length
- **Auto-backup** — Creates timestamped backups before any modification, with configurable retention
- **JSON report export** — Machine-readable summary of all changes

## Quick Start

```bash
# Preview changes (no files modified)
python3 zsh_smart_cleaner.py --dry-run

# Run with confirmation prompt
python3 zsh_smart_cleaner.py

# Skip confirmation (for scripts/CI)
python3 zsh_smart_cleaner.py --yes

# Analyze your history without changes
python3 zsh_smart_cleaner.py --analyze

# Scan for leaked tokens/secrets
python3 zsh_smart_cleaner.py --security-report
```

## Installation

No installation needed. Requires Python 3.6+.

```bash
git clone https://github.com/YOUR_USERNAME/zsh-smart-cleaner.git
cd zsh-smart-cleaner
```

Optionally add an alias to your `~/.zshrc`:

```bash
alias zsh-clean='python3 /path/to/zsh_smart_cleaner.py'
alias zsh-clean-dry='python3 /path/to/zsh_smart_cleaner.py --dry-run --verbose'
alias zsh-analyze='python3 /path/to/zsh_smart_cleaner.py --analyze'
```

## Usage

```
python3 zsh_smart_cleaner.py [history_file] [options]
```

### Options

| Flag | Description |
|---|---|
| `--dry-run` | Preview changes without modifying the history file |
| `--analyze` | Show history statistics (top commands, executables, duplicates) |
| `--security-report` | Scan for real tokens/secrets in history (informational only) |
| `--yes`, `-y` | Skip confirmation prompt |
| `--verbose`, `-v` | Show detailed removal reasons |
| `--max-lines N` | Keep only the last N entries |
| `--max-length N` | Maximum command length in characters (default: 500) |
| `--max-burst N` | Max consecutive identical commands to keep (default: 2) |
| `--no-burst-dedup` | Disable burst deduplication |
| `--keep-duplicates`, `-k` | Do not remove duplicate commands |
| `--remove-between START END` | Remove commands between two dates (YYYY-MM-DD) |
| `--config PATH` | Path to config file (default: `~/.zsh_smart_cleaner.json`) |
| `--no-backup` | Skip backup creation (USE WITH CAUTION) |
| `--report-json PATH` | Write machine-readable JSON report to PATH |
| `--top-n N` | Number of top items to show in analysis (default: 15) |

### Examples

```bash
# Dry run with verbose output
python3 zsh_smart_cleaner.py --dry-run --verbose

# Clean and export JSON report
python3 zsh_smart_cleaner.py --yes --report-json ~/clean-report.json

# Remove all commands from 2023
python3 zsh_smart_cleaner.py --remove-between 2023-01-01 2023-12-31 --yes

# Keep only last 3000 entries, skip backup
python3 zsh_smart_cleaner.py --max-lines 3000 --no-backup --yes

# Analyze history
python3 zsh_smart_cleaner.py --analyze --top-n 20

# Scan for security issues
python3 zsh_smart_cleaner.py --security-report
```

## Configuration

Copy the example config to get started:

```bash
cp example-config.json ~/.zsh_smart_cleaner.json
```

Then edit `~/.zsh_smart_cleaner.json` to customize rules for your workflow:

```json
{
  "ignore_list": [
    {"pattern": "^git(\\s|$)", "match_type": "regex", "description": "Keep git commands"},
    {"pattern": "^kubectl(\\s|$)", "match_type": "regex", "description": "Keep kubectl commands"},
    {"pattern": "^ssh(\\s|$)", "match_type": "regex", "description": "Keep ssh commands"}
  ],
  "allow_list": [
    {"pattern": "^clear$", "match_type": "regex", "description": "Remove standalone clear"},
    {"pattern": "^exit$", "match_type": "regex", "description": "Remove standalone exit"},
    {"pattern": "curl.*Authorization.*Token", "match_type": "regex", "description": "Remove curl with auth tokens"}
  ],
  "defaults": {
    "max_length": 500,
    "backup_retention": 10,
    "max_burst": 2
  }
}
```

### Rule Types

| `match_type` | Behavior |
|---|---|
| `exact` | Command must exactly match the pattern |
| `contains` | Command must contain the pattern as a substring |
| `starts_with` | Command must start with the pattern |
| `ends_with` | Command must end with the pattern |
| `regex` | Pattern is treated as a case-insensitive regex |

### Allow List vs Ignore List

- **Allow list** — Commands matching these rules are **removed** (e.g., `clear`, `exit`, curl with auth tokens)
- **Ignore list** — Commands matching these rules are **kept** (e.g., `git`, `kubectl`, `ssh`)

Processing order: allow list → malformed → pattern garbage → env prefix → burst dedup → ignore list → length check → global dedup

## Cleaning Pipeline

1. **Parse** — Reads ZSH extended history format with multiline support
2. **Allow list** — Removes commands matching allow-list rules
3. **Malformed detection** — Removes commands with unclosed quotes, unmatched parentheses, unfinished variable substitutions
4. **Pattern garbage** — Removes bare `\` or `/` lines, empty echo commands
5. **Env prefix** — Removes commands that are only env var assignments (`ENV=prod SERVICE=api`)
6. **Burst dedup** — Keeps newest N consecutive identical commands (default: 2)
7. **Ignore list** — Protects matching commands from further filtering
8. **Length check** — Removes commands exceeding max length
9. **Global dedup** — Removes duplicate commands (newest kept)
10. **Max-lines** — Truncates to last N entries if `--max-lines` is set

## Security Scanner

The `--security-report` flag scans your history for:

- **Auth tokens** — Hex or base64 tokens in `Authorization: Token <value>` headers
- **CSRF tokens** — Tokens in `X-CSRFToken: <value>` headers

This is **informational only** — it never modifies or removes entries. Use the allow list to remove commands containing tokens during cleaning.

## After Cleaning

Reload your history in the current zsh session:

```bash
fc -R
```

## Backup

Before any modification, a timestamped backup is created:

```
~/.zsh_history.backup_20260528_143022
```

Old backups are pruned to the configured retention count (default: 10). Restore manually:

```bash
cp ~/.zsh_history.backup_YYYYMMDD_HHMMSS ~/.zsh_history
fc -R
```

## Design Principles

- **Zero dependencies** — Single Python file, no pip install needed
- **Security-first** — Backup before write, restore on failure, TTY check for non-interactive use
- **No overfitting** — No UUID normalization, no semantic URL dedup, preserves meaningful history
- **Configurable** — Edit the JSON config to customize rules for your workflow
- **Transparent** — `--dry-run` and `--verbose` show exactly what will happen before any changes

## License

MIT
