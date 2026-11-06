#!/bin/bash
# start the relay and this desk's messenger client(s) if they are not running.
# Accounts and ports come from ~/.local/share/zenos/msg/ports.env (one line per account: name=port).
# In development the file also lists the demo devices (sato, tanaka, suzuki, press).
M="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
DATA="$HOME/.local/share/zenos/msg"
mkdir -p "$DATA"
cd "$DATA"
[ -f ports.env ] || echo "zenos=8096" > ports.env
# the local relay's directory (who is which clearance and organization) starts as the demo list; a ministry's relay
# keeps its own, set by its administrator (POST /directory)
mkdir -p "$DATA/relay"; [ -f "$DATA/relay/directory.json" ] || install -m 600 "$M/demo-directory.json" "$DATA/relay/directory.json"
pgrep -u "$(id -u)" -f "node $M/relay.js" >/dev/null || setsid /usr/bin/node "$M/relay.js" >"${XDG_RUNTIME_DIR:-$HOME/.cache}/zenos-relay.log" 2>&1 < /dev/null &
sleep 1
while IFS='=' read -r a p; do
  if [ -z "$a" ] || [ "${a#\#}" != "$a" ]; then continue; fi
  # started by zenos-launchd (root) when it is there: only such a messenger may carry the phone's answers to the vault
  pgrep -u "$(id -u)" -f "node $M/client.js $a " >/dev/null || python3 -I "$M/../bin/zenos_launch.py" messenger "$a" "$p" 2>/dev/null \
    || setsid /usr/bin/node "$M/client.js" "$a" "$p" >"${XDG_RUNTIME_DIR:-$HOME/.cache}/zenos-msg-$a.log" 2>&1 < /dev/null &
done < ports.env
