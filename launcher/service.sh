#!/system/bin/sh
# AxManager plugin boot hook: self-heal the payload, then bring root up.
# Runs as the shell uid; ytrl.sh re-execs itself under su once root exists.
LOG=/data/local/tmp/yt-plugin.log
exec >>"$LOG" 2>&1
echo "=== $(date) service.sh v5 uid=$(id -u) kernel=$(uname -r)"

D=$(dirname "$0")
# Sync every payload file by content: a panic can leave a file NUL-filled while
# its size stays correct, and a stale binary silently keeps old behaviour.
for f in plant su98260 ksud ytrl.sh; do
    [ -s "$D/$f" ] || continue
    if [ ! -s "/data/local/tmp/$f" ] || ! cmp -s "$D/$f" "/data/local/tmp/$f" 2>/dev/null; then
        cp -f "$D/$f" "/data/local/tmp/$f" 2>/dev/null && chmod 755 "/data/local/tmp/$f" 2>/dev/null && echo "synced $f"
    fi
done

# A plant parked on the UAF page must never be killed: a live lock means another
# run is already in charge.
if [ -f /data/local/tmp/.ytrl.lock/pid ]; then
    P=$(cat /data/local/tmp/.ytrl.lock/pid 2>/dev/null)
    if [ -n "${P:-}" ] && kill -0 "$P" 2>/dev/null; then echo "skip: running pid=$P"; exit 0; fi
fi

n=0
while [ $n -lt 60 ]; do
    [ "$(getprop sys.boot_completed)" = 1 ] && break
    sleep 1; n=$((n+1))
done
while [ "$(getprop init.svc.adbd)" != running ] && [ $n -lt 240 ]; do
    sleep 0.2; n=$((n+1))
done
echo "ready: boot=$(getprop sys.boot_completed) adbd=$(getprop init.svc.adbd) waited=${n}"
setsid /system/bin/sh /data/local/tmp/ytrl.sh start >>"$LOG" 2>&1 &
echo "spawned ytrl pid=$!"
