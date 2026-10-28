package testutils

import (
	"os"
	"runtime"
	"testing"
)

func TestExecuteInDirectoryRestoresAfterReturn(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(original) }()
	directory := t.TempDir()
	ExecuteInDirectory(t, directory, func() {
		current, err := os.Getwd()
		if err != nil {
			t.Fatalf("working directory inside callback = %q, %v; want %q", current, err, directory)
		}
		got, gotErr := os.Stat(current)
		want, wantErr := os.Stat(directory)
		if gotErr != nil || wantErr != nil || !os.SameFile(got, want) {
			t.Fatalf("working directory inside callback = %q, want %q", current, directory)
		}
	})
	current, err := os.Getwd()
	if err != nil || current != original {
		t.Fatalf("working directory after return = %q, %v; want %q", current, err, original)
	}
}

func TestExecuteInDirectoryRestoresAfterPanic(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(original) }()
	directory := t.TempDir()
	const expected = "intentional panic"
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		ExecuteInDirectory(t, directory, func() { panic(expected) })
	}()
	if recovered != expected {
		t.Fatalf("panic = %v, want %q", recovered, expected)
	}
	current, err := os.Getwd()
	if err != nil || current != original {
		t.Fatalf("working directory after panic = %q, %v; want %q", current, err, original)
	}
}

func TestExecuteInDirectoryRestoresAfterGoexit(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(original) }()
	directory := t.TempDir()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ExecuteInDirectory(t, directory, func() { runtime.Goexit() })
	}()
	<-done
	current, err := os.Getwd()
	if err != nil || current != original {
		t.Fatalf("working directory after Goexit = %q, %v; want %q", current, err, original)
	}
}
