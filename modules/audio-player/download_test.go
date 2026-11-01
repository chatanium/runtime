package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testDownloadLimits() playerLimits {
	redirects := 1
	return playerLimits{MaxDownloadBytes: 8, Workers: 2, MaxRedirects: &redirects, httpTimeout: time.Second}
}

func TestDownloadAttachmentUsesGeneratedOwnedPaths(t *testing.T) {
	base := t.TempDir()
	scratch, err := openScratch(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scratch.Close(); err != nil {
			t.Error(err)
		}
	})
	dir, err := scratch.directory()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "audio") }))
	defer server.Close()
	d := newAttachmentDownloader(testDownloadLimits())
	defer d.close()
	for _, name := range []string{"../../outside.mp3", "/outside.mp3", "same.mp3", "same.mp3", "../link/escape.opus"} {
		file, err := d.DownloadAttachment(context.Background(), attachment{URL: server.URL, Filename: name, Size: 5}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(file.path) != dir.path || strings.Contains(file.name, "/") || file.name == name {
			t.Fatalf("attachment name controlled scratch path: %q", file.path)
		}
		data, err := dir.root.ReadFile(file.name)
		if err != nil || string(data) != "audio" {
			t.Fatalf("download bytes=%q err=%v", data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(base, "outside.mp3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected external file: %v", err)
	}
}

func TestDownloadRejectsHTTPFailuresAndBoundsActualBytes(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"status", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "audio")
		}},
		{"content-length", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "9")
			_, _ = io.WriteString(w, "123456789")
		}},
		{"chunked-actual", func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "123456789")
		}},
		{"empty", func(w http.ResponseWriter, _ *http.Request) {}},
		{"truncated", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "8")
			_, _ = io.WriteString(w, "one")
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			scratch, err := openScratch(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer scratch.Close()
			dir, err := scratch.directory()
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			server := httptest.NewServer(scenario.handler)
			defer server.Close()
			d := newAttachmentDownloader(testDownloadLimits())
			defer d.close()
			file, err := d.DownloadAttachment(context.Background(), attachment{URL: server.URL, Filename: "a.mp3"}, dir)
			if err == nil || file != nil {
				t.Fatalf("failed input published file=%v err=%v", file, err)
			}
			entries, err := os.ReadDir(dir.path)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial files remain: %v err=%v", entries, err)
			}
		})
	}
}

func TestDownloadRedirectLimitAndCancellation(t *testing.T) {
	scratch, err := openScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	dir, err := scratch.directory()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()
	d := newAttachmentDownloader(testDownloadLimits())
	defer d.close()
	if _, err := d.DownloadAttachment(context.Background(), attachment{URL: server.URL, Filename: "a.mp3"}, dir); err == nil {
		t.Fatal("unbounded redirects succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.DownloadAttachment(ctx, attachment{URL: server.URL + "/slow", Filename: "a.mp3"}, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}

func TestScratchSymlinkCannotEscape(t *testing.T) {
	scratch, err := openScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	dir, err := scratch.directory()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir.path, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.root.OpenFile("link/escape", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600); err == nil {
		t.Fatal("os.Root followed an escaping symlink")
	}
}
