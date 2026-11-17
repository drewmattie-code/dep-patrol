#!/bin/bash
# Remove the monthly dep-patrol job installed by install-schedule.sh.
set -euo pipefail
if [ "$(uname)" = "Darwin" ]; then
  launchctl bootout "gui/$(id -u)/dev.dep-patrol.monthly" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/dev.dep-patrol.monthly.plist"
  echo "removed the launchd job"
else
  crontab -l 2>/dev/null | grep -v 'scan.py --config' | crontab - && echo "removed the crontab line"
fi
