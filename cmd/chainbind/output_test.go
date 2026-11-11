package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteOutput_StdoutAddsTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := writeOutput("", &buf, []byte("hello")); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	if got, want := buf.String(), "hello\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestWriteOutput_StdoutKeepsExistingNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := writeOutput("", &buf, []byte("hello\n")); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	if got, want := buf.String(), "hello\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestWriteOutput_StdoutEmptyDataWritesSingleNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := writeOutput("", &buf, nil); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	if got, want := buf.String(), "\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestWriteOutput_FileWritesExactBytesWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	data := []byte("no-newline-here")
	var buf bytes.Buffer
	if err := writeOutput(path, &buf, data); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("stdout written when path given: %q", buf.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("file content = %q, want %q (no newline must be added)", got, data)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %o, want 600", mode)
	}
}
