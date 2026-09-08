# ambxst-disclosure

PoC files for five vulnerabilities in Ambxst and axctl.

Reported privately to the maintainer on September 8, 2026. This repository goes public on December 7, 2026, when the 90-day window ends.

Write-up: <https://bnn.dev/blog/trust-but-grep>

| File | What it exploits |
|------|------------------|
| [`network_validate_test.go`](network_validate_test.go) | Wi-Fi SSID -> shell injection |
| [`clipboard_validate_test.go`](clipboard_validate_test.go) | Clipboard MIME -> SQL injection at insert |
| [`clipboard_validate_test.go`](clipboard_validate_test.go) | Stored MIME -> shell injection on re-copy |
| [`tmp_ipc_squat.sh`](tmp_ipc_squat.sh) | Squat of the fixed `/tmp/ambxst_ipc.pipe` |
| [`axctl_squat_test.go`](axctl_squat_test.go) | Squat of the fixed `/tmp/axctl-<uid>.sock` |
