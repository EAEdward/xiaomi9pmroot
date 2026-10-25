#!/system/bin/sh
# ytrl.sh v6 - yingtian root launcher core (module + xposed recovery)
# usage: ytrl.sh [status|start|force]
# NEVER kill a plant process: one holding the UAF page panics the kernel.
set -u
PATH=/system/bin:$PATH
PLANT=/data/local/tmp/plant
SU98260=/data/local/tmp/su98260
KSUD=/data/local/tmp/ksud
SUBIN=/system/bin/su
SOCK=/data/local/tmp/pc98260-root.sock
LOG=/data/local/tmp/root.log
STATUS=/data/local/tmp/ytrl.status
LOCK=/data/local/tmp/.ytrl.lock
TICKS=300

log() { echo "[$(date '+%H:%M:%S')] $*" >>"$LOG" 2>/dev/null; }
# 'cmd notification' starts app_process (~200-400 ms); keep it off the
# critical path.
# Silent by default: no heads-up notifications at boot. `touch /data/local/tmp/ytrl.notify`
# turns them back on for debugging.
if [ -f /data/local/tmp/ytrl.notify ]; then
    notify() { ( cmd notification post -S bigtext -t "$1" ytroot "$2" >/dev/null 2>&1 & ) ; }
else
    notify() { :; }
fi
have_ksu() { "$SUBIN" -c true >/dev/null 2>&1; }
have_sock() { "$SU98260" -c true >/dev/null 2>&1; }
plant_running() { [ -n "$(pidof plant 2>/dev/null)" ]; }
now() { date +%s; }

# ---- module recovery -------------------------------------------------------
# Late-loaded KSU never ran the boot-time post-fs-data/services stages, so:
#   1) replay them (sepolicy + module scripts);
#   2) start the module daemons with `ksud services` (it carries KSU env);
#   3) restart zygote ONCE per boot so Zygisk Next can inject into a fresh one
#      (verified: /proc/<zygote>/maps shows libzygisk + the LSPosed/Vector .so,
#      and system_server inherits it);
#   4) run services again so the framework daemons come up post-injection.
KSUD_BIN=/data/adb/ksud
# /data/adb/ksud is installed by ksud itself and can lag behind the first
# boot stage; the payload copy always exists.
[ -x "$KSUD_BIN" ] || KSUD_BIN=/data/local/tmp/ksud
MODMARK=/data/local/tmp/.ytrl.stage
MODSTATE=/data/local/tmp/ytrl.modules
BOOTID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
ZRESTART=/data/local/tmp/.ytrl.zygote.$BOOTID

mod_state() {
    printf '{"zn":"%s","lspd":"%s","zygote":"%s","injected":"%s"}\n' \
        "$(pidof zn-daemon 2>/dev/null | awk '{print $1}')" \
        "$(pidof lspd 2>/dev/null | awk '{print $1}')" \
        "$(pidof zygote64 2>/dev/null | awk '{print $1}')" \
        "$(zygote_maps)" >"$MODSTATE" 2>/dev/null
    chmod 666 "$MODSTATE" 2>/dev/null
}

zygote_maps() {
    z=$(pidof zygote64 2>/dev/null | awk '{print $1}')
    [ -n "$z" ] || { echo 0; return; }
    n=$(grep -ic zygisk /proc/$z/maps 2>/dev/null)
    echo "${n:-0}"
}

dedupe_zn() {
    pids=$(pidof zn-daemon 2>/dev/null)
    [ -n "$pids" ] || return 0
    keep=""
    for p in $pids; do keep=$p; done
    for p in $pids; do [ "$p" = "$keep" ] || kill -9 "$p" 2>/dev/null; done
}

inject_xposed() {
    m=$(zygote_maps)
    if [ "${m:-0}" -gt 0 ]; then log "inject: active maps=$m"; return 0; fi
    z=$(pidof zygote64 2>/dev/null | awk '{print $1}')
    n=$(cut -d: -f1 "$ZRESTART" 2>/dev/null)
    last=$(cut -d: -f2 "$ZRESTART" 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    if [ "$n" -ge 3 ]; then log "inject: restart budget spent ($n)"; return 1; fi
    if [ -n "$last" ] && [ "$last" = "$z" ]; then log "inject: zygote $z already handled"; return 1; fi
    # Zygisk Next injects once per daemon generation: refresh the daemon
    # right before the restart, otherwise the second zygote comes back clean.
    for p in $(pidof zn-daemon 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
    ( cd /data/adb/modules/zygisksu && setsid sh ./post-fs-data.sh >>"$LOG" 2>&1 </dev/null & )
    sleep 3
    dedupe_zn
    if [ -z "$(pidof zn-daemon 2>/dev/null)" ]; then log 'inject: no zn-daemon'; return 1; fi
    echo "$((n + 1)):$z" >"$ZRESTART" 2>/dev/null
    log 'inject: restarting zygote once for zygisk'
    notify '注入 Xposed' '重启系统框架，约 20 秒'
    setprop ctl.restart zygote >>"$LOG" 2>&1
    i=0
    while [ "$i" -lt 30 ]; do
        sleep 1; i=$((i + 1))
        [ "$(zygote_maps)" -gt 0 ] && { log "inject: ok after ${i}s maps=$(zygote_maps)"; mod_state; return 0; }
    done
    log 'inject: zygote came back without zygisk'
    return 1
}

stage_modules() {
    if [ ! -x "$KSUD_BIN" ]; then log 'stage: ksud missing'; return 1; fi
    if [ ! -f "$MODMARK" ]; then
        ( setsid "$KSUD_BIN" post-fs-data >>"$LOG" 2>&1 </dev/null & )
        : >"$MODMARK" 2>/dev/null
        log 'stage: post-fs-data launched'
        sleep 1
    fi
    if [ -z "$(pidof zn-daemon 2>/dev/null)" ]; then
        # zygiskd is started by the module post-fs-data script; the KSU
        # services stage is a no-op for it when ZYGISK_ENABLED=1.
        ( cd /data/adb/modules/zygisksu && setsid sh ./post-fs-data.sh >>"$LOG" 2>&1 </dev/null & )
        sleep 3
        dedupe_zn
        log "stage: zygiskd zn=$(pidof zn-daemon | awk '{print $1}')"
    fi
    if [ -z "$(pidof lspd 2>/dev/null)" ]; then
        ( setsid "$KSUD_BIN" services >>"$LOG" 2>&1 </dev/null & )
        sleep 2
        dedupe_zn
        log "stage: services lspd=$(pidof lspd | awk '{print $1}')"
    fi
    inject_xposed
    if [ -n "$(pidof zn-daemon 2>/dev/null)" ]; then
        ( setsid "$KSUD_BIN" services >>"$LOG" 2>&1 </dev/null & )
        sleep 2
        dedupe_zn
    fi
    "$KSUD_BIN" kernel notify-module-mounted >>"$LOG" 2>&1
    # Vector (the Android 17 Xposed framework) ships a wrapper this ROM
    # cannot run (toybox unshare lacks --propagation); start it directly.
    if [ -z "$(pidof vectord 2>/dev/null)" ] && [ -f /data/adb/modules/zygisk_vector/daemon.apk ]; then
        V=/data/adb/modules/zygisk_vector
        ( setsid /system/bin/app_process -Djava.class.path="$V/daemon.apk" /system/bin \
            --nice-name=vectord org.matrix.vector.daemon.VectorDaemon >>"$LOG" 2>&1 </dev/null & )
        sleep 4
        log "stage: vectord=$(pidof vectord | awk '{print $1}')"
    fi
    start_apps
    log "stage: done $(mod_state)"
    mod_state
    return 0
}

# Generic module supervisor: <name> <check> <restart command>
#   check = pidfile:/path | pidof:name
MODS_CONF=/data/local/tmp/ytrl.mods
supervise_modules() {
    [ -f "$MODS_CONF" ] || return 0
    while read -r mname mcheck mcmd; do
        case "$mname" in ""|\#*) continue ;; esac
        alive=0
        case "$mcheck" in
            pidfile:*)
                pf=${mcheck#pidfile:}
                mp=$(cat "$pf" 2>/dev/null)
                [ -n "$mp" ] && kill -0 "$mp" 2>/dev/null && alive=1
                ;;
            pidof:*)
                [ -n "$(pidof "${mcheck#pidof:}" 2>/dev/null)" ] && alive=1
                ;;
        esac
        if [ "$alive" = 0 ]; then
            log "watch: module $mname down, restarting"
            ( setsid sh -c "$mcmd" >>"$LOG" 2>&1 </dev/null & )
        fi
    done <"$MODS_CONF"
}

# Apps to pre-warm at boot (and restart if they die). Format:
#   <package>/<activity>   foreground|background
# dpinviewer ships no BOOT_COMPLETED receiver, so nothing else will start it.
APPS_CONF=/data/local/tmp/ytrl.apps

start_apps() {
    [ -f "$APPS_CONF" ] || return 0
    while read -r acomp amode; do
        case "$acomp" in ""|\#*) continue ;; esac
        case "$acomp" in */*) ;; *) continue ;; esac
        apkg=${acomp%%/*}
        if [ -n "$(pidof "$apkg" 2>/dev/null)" ]; then
            log "apps: $apkg already running"
            continue
        fi
        tries=0
        while [ "$tries" -lt 6 ]; do
            tries=$((tries + 1))
            /system/bin/am start --user 0 -n "$acomp" >>"$LOG" 2>&1
            sleep 3
            [ -n "$(pidof "$apkg" 2>/dev/null)" ] && break
        done
        log "apps: $acomp try=$tries pid=$(pidof "$apkg" 2>/dev/null | awk '{print $1}')"
        if [ "${amode:-foreground}" = background ]; then
            sleep 2
            /system/bin/input keyevent KEYCODE_HOME >>"$LOG" 2>&1
            log 'apps: sent HOME'
        fi
    done <"$APPS_CONF"
}

# Ghost-style front end bridge. The APK (dev.yt.ghostroot) is a controller: it
# cannot run the exploit itself (needs uid 2000), so it drops commands here and
# this root-side poller executes them and mirrors the state back.
GHOST_DIR=/data/media/0/Android/data/dev.yt.ghostroot/files

ghost_bridge() {
    [ -d "$GHOST_DIR" ] || mkdir -p "$GHOST_DIR" 2>/dev/null
    [ -d "$GHOST_DIR" ] || return 0
    cp -f /data/local/tmp/ytrl.status "$GHOST_DIR/ytrl.status" 2>/dev/null
    cp -f /data/local/tmp/ytrl.modules "$GHOST_DIR/ytrl.modules" 2>/dev/null
    chmod 666 "$GHOST_DIR"/ytrl.status "$GHOST_DIR"/ytrl.modules 2>/dev/null
    [ -s "$GHOST_DIR/ytrl.cmd" ] || return 0
    c=$(tr -d " \t\r\n\000" <"$GHOST_DIR/ytrl.cmd" 2>/dev/null)
    : >"$GHOST_DIR/ytrl.cmd" 2>/dev/null
    log "ghost: cmd=$c"
    case "$c" in
        start) sh "$0" start >>"$LOG" 2>&1 ;;
        modules) stage_modules soft >>"$LOG" 2>&1 ;;
        apps) start_apps >>"$LOG" 2>&1 ;;
        *) log "ghost: unknown cmd $c" ;;
    esac
    cp -f /data/local/tmp/ytrl.status "$GHOST_DIR/ytrl.status" 2>/dev/null
    chmod 666 "$GHOST_DIR"/ytrl.status 2>/dev/null
}

ghost_loop() {
    while :; do
        ghost_bridge
        sleep 2
    done
}

watch_modules() {
    last_z=$(pidof zygote64 2>/dev/null | awk '{print $1}')
    while :; do
        sleep 30
        z=$(pidof zygote64 2>/dev/null | awk '{print $1}')
        if [ -n "$z" ] && [ "$z" != "$last_z" ]; then
            log "watch: zygote $last_z -> $z, re-notify"
            last_z=$z
            "$KSUD_BIN" kernel notify-module-mounted >>"$LOG" 2>&1
            inject_xposed
            [ -z "$(pidof zn-daemon 2>/dev/null)" ] && \
                ( setsid "$KSUD_BIN" services >>"$LOG" 2>&1 </dev/null & )
        fi
        if [ -z "$(pidof zn-daemon 2>/dev/null)" ] || [ -z "$(pidof lspd 2>/dev/null)" ]; then
            log 'watch: module daemons gone, restaging'
            stage_modules soft >>"$LOG" 2>&1
        fi
        supervise_modules
        mod_state
    done
}

write_status() {
    printf '{"state":"%s","detail":"%s","elapsed":%s,"ts":%s}\n' \
        "$1" "$2" "${ELAPSED:-0}" "$(date +%s)" >"$STATUS" 2>/dev/null
    chmod 666 "$STATUS" 2>/dev/null
}

# --check must never block the launch path; a hung probe just means unknown.
preflight() {
    out=$(timeout 20 "$PLANT" --check --quick 2>/dev/null | tail -1)
    log "preflight: ${out:-<timeout>}"
    case "$out" in
        *'"verdict":"ok"'*) return 0 ;;
        *'"verdict":"blocked"'*) return 1 ;;
    esac
    return 2
}

# Wait for the rootd socket, then load KernelSU off the critical path: 'su' is
# only needed for the module ecosystem, plain root works the moment the
# socket answers.
load_ksu() {
    if ! have_sock; then
        log 'rootd socket exists but does not answer'
        return 1
    fi
    ELAPSED=$(( $(now) - START ))
    log "rootd ready elapsed=${ELAPSED}s"
    write_status ready rootd
    notify 'Root 已就绪' "${ELAPSED} 秒完成（KSU 后台加载中）"
    # KMI follows the running kernel, not a hardcoded string: any yingtian
    # build reports e.g. 6.18.21-android17-5-g... -> android17-6.18
    R=$(uname -r 2>/dev/null)
    API=$(echo "$R" | sed -n "s/.*android\([0-9]*\).*/\1/p")
    KMV=$(echo "$R" | cut -d- -f1 | cut -d. -f1,2)
    [ -n "$API" ] && [ -n "$KMV" ] && KMI="android$API-$KMV"
    [ -n "$KMI" ] || KMI=android17-6.18
    log "late-load kmi=$KMI (uname=$(uname -r))"
    "$SU98260" -c "$KSUD late-load --kmi $KMI --allow-shell --package-name me.weishu.kernelsu" >>"$LOG" 2>&1
    n=0
    while [ "$n" -lt 150 ]; do have_ksu && break; sleep 0.2; n=$((n+1)); done
    ELAPSED=$(( $(now) - START ))
    if have_ksu; then
        log "OK ksu online elapsed=${ELAPSED}s"
        write_status ready ksu-online
        notify 'Root 已就绪' "${ELAPSED} 秒完成，KSU 在线"
    else
        log 'FAIL: su missing after late-load'
        write_status ready no-ksu
        notify 'Root 部分可用' '已 root，KSU 未接管，点图标重试'
    fi
    return 0
}

# Everything past this point needs privilege: ksud lives under /data/adb,
# and /proc/<pid>/maps of zygote is not readable as shell. The boot hook
# runs as shell, so re-exec under the plant su once.
if [ "$(id -u 2>/dev/null)" != "0" ]; then
    if "$SUBIN" -c true >/dev/null 2>&1; then
        exec "$SUBIN" -c "sh $0 $*"
    fi
    if [ -x "$SU98260" ] && "$SU98260" -c true >/dev/null 2>&1; then
        exec "$SU98260" -c "sh $0 $*"
    fi
    log "not root, no working su: running unprivileged"
fi

MODE=${1:-start}
MODARG=${2:-soft}
START=$(now)
mkdir -p /data/local/tmp 2>/dev/null
log "=== ytrl v4 mode=$MODE boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"

if [ "$MODE" = watch ]; then
    watch_modules
    exit 0
fi

if [ "$MODE" = ghost ]; then
    ghost_loop
    exit 0
fi

if [ "$MODE" = apps ]; then
    start_apps
    exit 0
fi

if [ "$MODE" = modules ]; then
    stage_modules "$MODARG"
    exit $?
fi

if [ "$MODE" = status ]; then
    if have_ksu; then echo root; exit 0; fi
    if have_sock; then echo socket-only; exit 0; fi
    echo none; exit 2
fi

if have_ksu; then
    ELAPSED=$(( $(now) - START ))
    log 'already root'; write_status ready already-root; echo ready; exit 0
fi

preflight; pf=$?
if [ "$pf" = 1 ]; then
    ELAPSED=$(( $(now) - START ))
    log 'preflight blocked: kernel/tracefs unsupported'
    write_status blocked preflight
    notify 'Root 不可用' '这台设备未通过预检，未执行提权'
    exit 1
fi
[ "$pf" = 2 ] && log 'preflight inconclusive, continuing'

# The socket file survives a reboot owned by root and shell cannot unlink it,
# so readiness must be a real connect, not a -S test.

# A leftover plant means the previous attempt is still parked. Killing it
# frees the reclaimed page underneath a live rb_node and panics the kernel.
if plant_running && ! have_sock; then
    log 'stale plant parked; refusing to kill it'
    write_status blocked stale-plant
    notify '需要重启' '上次提权卡住了，重启后会自动重试'
    # A parked plant can only be cleared by a reboot. Reboot ourselves,
    # but cap it per day so a broken build cannot loop forever.
    RC=/data/local/tmp/.ytrl.reboot.count
    today=$(date +%Y%m%d)
    cnt=$(cat "$RC" 2>/dev/null | cut -d: -f2)
    day=$(cat "$RC" 2>/dev/null | cut -d: -f1)
    [ "$day" = "$today" ] || cnt=0
    case "$cnt" in ""|*[!0-9]*) cnt=0 ;; esac
    if [ "$cnt" -lt 6 ]; then
        echo "$today:$((cnt + 1))" >"$RC" 2>/dev/null
        log "stale plant -> auto reboot ($((cnt + 1))/6 today)"
        sleep 5
        reboot -p 2>/dev/null || reboot
    fi
    log 'stale plant, reboot budget for today spent'
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

notify '正在获取 Root' '提权中，约 2 秒，请勿重启'
write_status working starting
log 'launching plant'
( cd /data/local/tmp && setsid nohup ./plant >>"$LOG" 2>&1 & ) 2>/dev/null

n=0
while [ "$n" -lt "$TICKS" ]; do
    have_sock && break
    sleep 0.3; n=$((n+1))
done

if ! have_sock; then
    ELAPSED=$(( $(now) - START ))
    log 'FAIL: no rootd socket'
    write_status failed no-root
    notify 'Root 失败' '点图标重试或重启设备'
    exit 1
fi

load_ksu
# The boot hook runs as shell: /data/adb (ksud) and /proc/<pid>/maps are
# out of reach, so the stage and both daemons have to be re-launched
# through the rootd helper once root exists.
if [ "$(id -u 2>/dev/null)" != "0" ] && "$SU98260" -c true >/dev/null 2>&1; then
    log "re-launching stage/daemons as root (was uid=$(id -u))"
    "$SU98260" -c "sh $0 modules $MODARG" >>"$LOG" 2>&1 &
    "$SU98260" -c "setsid sh $0 watch" >>"$LOG" 2>&1 </dev/null &
    "$SU98260" -c "setsid sh $0 ghost" >>"$LOG" 2>&1 </dev/null &
else
    stage_modules "$MODARG"
    ( setsid sh "$0" watch >>"$LOG" 2>&1 </dev/null & ) 2>/dev/null
    ( setsid sh "$0" ghost >>"$LOG" 2>&1 </dev/null & ) 2>/dev/null
fi
