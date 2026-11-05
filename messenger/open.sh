#!/bin/bash
# open the messenger window for one device (default: this desk's user); a second argument opens a view (calendar)
M="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
R="$(dirname "$M")"
"$M/start.sh"
sleep 2
A=${1:-zenos}
V=${2:-}
case $A in zenos) P=8096;; sato) P=8097;; tanaka) P=8098;; suzuki) P=8099;; esac
T="ZENOS Messages"; [ "$A" != zenos ] && T="ZENOS Messages · $A (demo device)"
I="$R/icons/zenos-messenger.svg"
case $V in
  calendar) T="ZENOS Calendar"; I="$R/icons/zenos-calendar.svg";;
  requests) T="ZENOS Approvals"; I="$R/icons/zenos-approvals.svg";;
  *) V="";;
esac
K=""; for i in 1 2 3 4 5; do K=$(cat "$HOME/.local/share/zenos/msg/store/$A/local.key" 2>/dev/null) && [ -n "$K" ] && break; sleep 1; done
# the key goes through the environment (readable only by this account), never the command line (readable by everyone)
ZENOS_WEBAPP_START="http://127.0.0.1:$P/open?k=$K${V:+#$V}" setsid python3 "$M/zenos_webapp.py" "http://127.0.0.1:$P/${V:+#$V}" "$T" "$I" 980x620 >"/tmp/zenos-msgwin-$A.log" 2>&1 < /dev/null &
