#!/usr/bin/env python3
"""ZENOS sensor liveness (dead-man's switch, PoC).

emitter: stands in for the resident sensor. Writes a heartbeat every INTERVAL seconds.
watcher: stands in for ANOTHER node. If the heartbeat goes stale past TIMEOUT, it raises an alarm
         and writes it to the tamper-evident ledger. Silencing the sensor is therefore itself the
         loudest event, and the alarm lives on a different node than the one being attacked.
"""
import os, sys, time
# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
import zledger
try:
    import zalarm
except Exception:
    zalarm = None

HB = "/run/zenos-sensor.hb"
LEDGER = "/var/log/zenos/access-ledger.jsonl"
INTERVAL = 1.0
TIMEOUT = 10.0      # a loaded machine can miss a few beats; a stopped sensor is silent for good
GRACE = 180.0       # after boot the sensor (netsentinel, bpftrace) needs time to start


def beat():
    """write the heartbeat atomically: a reader sees the old value or the new one, never an empty file"""
    tmp = HB + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(time.time()))
    os.replace(tmp, HB)


def emitter():
    while True:
        beat()
        time.sleep(INTERVAL)


def read_beat():
    try:
        with open(HB) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def read_beat_settled(tries=3, gap=0.06):
    """a writer that rewrites the file in place leaves it empty for a moment; one empty read is
    not silence, so look again shortly before treating the beat as unreadable"""
    b = read_beat()
    for _ in range(tries - 1):
        if b is not None:
            break
        time.sleep(gap)
        b = read_beat()
    return b


def watcher(run_sec):
    run_sec = float(run_sec)
    forever = run_sec <= 0
    t0 = time.time()
    alarmed = False
    last = None                       # the last heartbeat this watcher could read
    while forever or time.time() - t0 < run_sec:
        b = read_beat_settled()
        if b is not None:
            last = b if last is None else max(last, b)
        now = time.time()
        if last is None:              # never seen one: silent only once the start-up grace is over
            age = now - t0 if now - t0 > GRACE else 0
        else:
            age = now - last
        if age <= TIMEOUT and alarmed:
            zledger.append(LEDGER, 'sensor-recovered', 'node-B', 'watcher', target='node-A')
            print('recovered: heartbeat fresh again', flush=True); alarmed = False  # re-arm
        if age > TIMEOUT and not alarmed:
            detect = round(age, 2)
            zledger.append(LEDGER, "sensor-silenced", "node-B", "watcher",
                           target="node-A", stale_sec=detect, action="escalate", never_started=last is None)
            print("ALARM: sensor silenced, heartbeat stale %.2fs -> escalate" % detect, flush=True)
            if zalarm is not None:
                try:
                    zalarm.raise_alert("red", "ZENOS RED ALERT", "sensor silenced %.2fs -> escalate" % detect)
                except Exception:
                    pass
            alarmed = True
        time.sleep(0.5)
    if not alarmed:
        print("no alarm: heartbeat stayed fresh", flush=True)


if __name__ == "__main__":
    globals()[sys.argv[1]](*sys.argv[2:])
