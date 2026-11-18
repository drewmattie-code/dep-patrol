#!/bin/bash
# Install a monthly dep-patrol run (1st of the month, 09:00).
#   macOS: a launchd agent (runs at next wake if the Mac was asleep)
#   Linux: a crontab line
# usage: scripts/install-schedule.sh [--dry-run] [config path]   (default ~/.dep-patrol/config.json)
#   --dry-run prints which Python and command would be scheduled, and installs nothing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
CONFIG="${1:-$HOME/.dep-patrol/config.json}"
# Pick a Python that can read poetry.lock and uv.lock (3.11+). The first python3 on PATH is often the old system
# one, above all over ssh and under launchd.
PY=""; FIRST=""
for cand in ${DEP_PATROL_PYTHONS:-$(command -v python3 || true) /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3}; do
  [ -x "$cand" ] || continue
  [ -n "$FIRST" ] || FIRST="$cand"
  if [ "$("$cand" -c 'import sys; print(sys.version_info >= (3, 11))' 2>/dev/null)" = "True" ]; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  [ -n "$FIRST" ] || { echo "no python3 found"; exit 1; }
  PY="$FIRST"
  echo "warning: $PY is older than Python 3.11, so poetry.lock and uv.lock will be reported as not scanned."
  echo "         Install a newer Python (or 'pip install tomli' for this one) and run this again."
fi
[ -f "$CONFIG" ] || { echo "no config at $CONFIG (copy dep-patrol.example.json there first)"; exit 1; }
if [ $DRY = 1 ]; then echo "python: $PY"; echo "would run monthly: $PY $HERE/scan.py --config $CONFIG --notify"; exit 0; fi
mkdir -p "$HOME/.dep-patrol"
if [ "$(uname)" = "Darwin" ]; then
  PL="$HOME/Library/LaunchAgents/dev.dep-patrol.monthly.plist"
  cat > "$PL" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.dep-patrol.monthly</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>$HERE/scan.py</string><string>--config</string><string>$CONFIG</string><string>--notify</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>RunAtLoad</key><false/>
  <key>ThrottleInterval</key><integer>3600</integer>
  <key>StartCalendarInterval</key><dict><key>Day</key><integer>1</integer><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>$HOME/.dep-patrol/last-run.log</string>
  <key>StandardErrorPath</key><string>$HOME/.dep-patrol/last-run.log</string>
</dict></plist>
EOF
  launchctl bootout "gui/$(id -u)/dev.dep-patrol.monthly" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PL"
  echo "installed $PL (runs the 1st of each month at 09:00)"
  echo "run it now:   launchctl kickstart gui/$(id -u)/dev.dep-patrol.monthly"
  echo "last run:     cat ~/.dep-patrol/last-run.log   (reports in ~/.dep-patrol/reports/)"
  echo "remove it:    $HERE/uninstall-schedule.sh"
else
  LINE="0 9 1 * * $PY $HERE/scan.py --config $CONFIG --notify >> $HOME/.dep-patrol/last-run.log 2>&1"
  ( crontab -l 2>/dev/null | grep -v 'dep-patrol/.*/scan.py\|scan.py --config' ; echo "$LINE" ) | crontab -
  echo "installed crontab line: $LINE"
fi
