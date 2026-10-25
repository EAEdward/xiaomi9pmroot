#!/system/bin/sh
# xiaomi9pmroot — root only.
#
#   plant  ->  rootd  ->  KernelSU (late-load)  ->  user scripts
#
# Nothing here touches Zygisk / LSPosed / module mounting. The only privileged
# jobs are: run the exploit, load kernelsu.ko, and execute your own scripts as
# root. Invoke it from AxManager (plugin) or from a Shizuku shell.
#
# usage: ytrl.sh [start|force|status|scripts|check]
set -u
PATH=/system/bin:$PATH
PLANT=/data/local/tmp/plant
SU98260=/data/local/tmp/su98260
KSUD=/data/local/tmp/ksud
SUBIN=/system/bin/su
SOCK=/data/local/tmp/pc98260-root.sock
LOG=/data/local/tmp/root.log
STATUS=/data/local/tmp/ytrl.status
LOCK=/data/local/tmp/.ytroot.lock
SCRIPTS=/data/local/tmp/yt-scripts
TICKS=300

log() { echo "[$(date '+%H:%M:%S')] $*" >>"$LOG" 2>/dev/null; }

# Silent by default; `touch /data/local/tmp/ytrl.notify` to get notifications.
if [ -f /data/local/tmp/ytrl.notify ]; then
    notify() { ( cmd notification post -S bigtext -t "$1" ytroot "$2" >/dev/null 2>&1 & ) ; }
else
    notify() { :; }
fi

now() { date +%s; }

write_status() {
    printf '{"state":"%s","detail":"%s","elapsed":%s,"ts":%s}\n' \
        "$1" "$2" "${ELAPSED:-0}" "$(date +%s)" >"$STATUS" 2>/dev/null
    chmod 666 "$STATUS" 2>/dev/null
}

have_ksu() { "$SUBIN" -c true >/dev/null 2>&1; }
have_rootd() { "$SU98260" -c true >/dev/null 2>&1; }

# Preflight never blocks the launch path: a hung probe just means "unknown".
preflight() {
    out=$(timeout 20 "$PLANT" --check --quick 2>/dev/null | tail -1)
    log "preflight: ${out:-<timeout>}"
    case "$out" in
        *'"verdict":"ok"'*) return 0 ;;
        *'"verdict":"blocked"'*) return 1 ;;
    esac
    return 2
}

# KMI follows the running kernel: 6.18.21-android17-5-g... -> android17-6.18
kmi() {
    R=$(uname -r 2>/dev/null)
    API=$(echo "$R" | sed -n "s/.*android\([0-9]*\).*/\1/p")
    KMV=$(echo "$R" | cut -d- -f1 | cut -d. -f1,2)
    if [ -n "$API" ] && [ -n "$KMV" ]; then echo "android$API-$KMV"; else echo android17-6.18; fi
}

load_ksu() {
    if ! have_rootd; then log "rootd socket is not answering"; return 1; fi
    ELAPSED=$(( $(now) - START ))
    log "rootd ready elapsed=${ELAPSED}s"
    write_status ready rootd
    notify 'Root 已就绪' "${ELAPSED} 秒"
    K=$(kmi)
    log "late-load kmi=$K (uname=$(uname -r))"
    "$SU98260" -c "$KSUD late-load --kmi $K --allow-shell --package-name me.weishu.kernelsu" >>"$LOG" 2>&1
    n=0
    while [ "$n" -lt 150 ]; do have_ksu && break; sleep 0.2; n=$((n+1)); done
    ELAPSED=$(( $(now) - START ))
    if have_ksu; then
        log "OK ksu online elapsed=${ELAPSED}s"
        write_status ready ksu-online
        notify 'Root 已就绪' "${ELAPSED} 秒，KSU 在线"
        return 0
    fi
    log 'FAIL: su missing after late-load'
    write_status ready no-ksu
    return 1
}

# Drop-in hook: every executable *.sh under $SCRIPTS runs once, as root, in name
# order, after root is usable. Output goes to $LOG.
run_scripts() {
    [ -d "$SCRIPTS" ] || { log "scripts: $SCRIPTS missing"; return 0; }
    for f in "$SCRIPTS"/*.sh; do
        [ -f "$f" ] || continue
        log "scripts: running $f"
        if have_ksu; then
            "$SUBIN" -c "sh $f" >>"$LOG" 2>&1
        else
            "$SU98260" -c "sh $f" >>"$LOG" 2>&1
        fi
        log "scripts: $f rc=$?"
    done
}

MODE=${1:-start}
START=$(now)
mkdir -p /data/local/tmp 2>/dev/null
log "=== ytrl mode=$MODE boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"

if [ "$MODE" = status ]; then
    if have_ksu; then echo root; exit 0; fi
    if have_rootd; then echo socket-only; exit 0; fi
    echo none; exit 2
fi

if [ "$MODE" = scripts ]; then
    run_scripts
    exit $?
fi

if [ "$MODE" = check ]; then
    preflight; echo "preflight=$?"
    exit 0
fi

if have_ksu; then
    ELAPSED=$(( $(now) - START ))
    log 'already root'
    write_status ready already-root
    run_scripts
    exit 0
fi

preflight
pf=$?
if [ "$pf" = 1 ]; then
    ELAPSED=$(( $(now) - START ))
    log 'preflight blocked: kernel/tracefs unsupported'
    write_status blocked preflight
    notify 'Root 不可用' '这台设备未通过预检'
    exit 1
fi
[ "$pf" = 2 ] && log 'preflight inconclusive, continuing'

# The socket file survives a reboot owned by root, so readiness must be a real
# connect, never a `[ -S ]` test. A parked plant must never be killed.
if [ -n "$(pidof plant 2>/dev/null)" ] && ! have_rootd; then
    log 'stale plant parked; refusing to kill it'
    write_status blocked stale-plant
    notify '需要重启' '上次提权卡住了，重启后会自动重试'
    RC=/data/local/tmp/.ytroot.reboot.count
    today=$(date +%Y%m%d)
    cnt=$(cut -d: -f2 "$RC" 2>/dev/null)
    day=$(cut -d: -f1 "$RC" 2>/dev/null)
    [ "$day" = "$today" ] || cnt=0
    case "$cnt" in ''|*[!0-9]*) cnt=0 ;; esac
    if [ "$cnt" -lt 6 ]; then
        echo "$today:$((cnt + 1))" >"$RC" 2>/dev/null
        log "stale plant -> auto reboot ($((cnt + 1))/6 today)"
        sleep 5
        reboot
    fi
    exit 4
fi

[ "$MODE" = force ] && rm -rf "$LOCK" 2>/dev/null
if ! mkdir "$LOCK" 2>/dev/null; then
    old=$(cat "$LOCK/pid" 2>/dev/null)
    if [ -n "${old:-}" ] && kill -0 "$old" 2>/dev/null; then log "busy pid=$old"; exit 3; fi
    rm -rf "$LOCK" 2>/dev/null; mkdir "$LOCK" 2>/dev/null || exit 3
fi
echo $$ >"$LOCK/pid"
trap 'rm -rf "$LOCK" 2>/dev/null' EXIT INT TERM

notify '正在获取 Root' '提权中，请稍候'
write_status working starting
log 'launching plant'
( cd /data/local/tmp && setsid nohup ./plant >>"$LOG" 2>&1 & ) 2>/dev/null

n=0
while [ "$n" -lt "$TICKS" ]; do
    have_rootd && break
    sleep 0.3; n=$((n+1))
done

if ! have_rootd; then
    ELAPSED=$(( $(now) - START ))
    log 'FAIL: no rootd socket'
    write_status failed no-root
    notify 'Root 失败' '点图标重试或重启设备'
    exit 1
fi

load_ksu
run_scripts
