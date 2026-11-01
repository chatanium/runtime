package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type responseBodyWithCloseError struct{ io.ReadCloser }

func (b responseBodyWithCloseError) Close() error {
	return errors.Join(b.ReadCloser.Close(), errors.New("fixture close failure"))
}

type wrappingTransport struct{ next http.RoundTripper }

func (t wrappingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(req)
	if err == nil {
		response.Body = responseBodyWithCloseError{response.Body}
	}
	return response, err
}

func TestDownloadBodyCloseFailureRemovesUnpublishedFile(t *testing.T) {
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "audio") }))
	defer server.Close()
	d := newAttachmentDownloader(testDownloadLimits())
	defer d.close()
	d.client.Transport = wrappingTransport{d.transport}
	file, err := d.DownloadAttachment(context.Background(), attachment{URL: server.URL, Filename: "a.mp3"}, dir)
	if err == nil || file != nil {
		t.Fatalf("body close failure published file=%v err=%v", file, err)
	}
	entries, err := os.ReadDir(dir.path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("close failure left artifact: %v err=%v", entries, err)
	}
}
