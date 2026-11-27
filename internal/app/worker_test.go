//go:build linux

package app

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/bootstrap"
)

func TestGvxWorkerRejectsControlBeforeInit(t *testing.T) {
	input, inputWriter := io.Pipe()
	outputReader, output := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	defer output.Close()
	defer outputReader.Close()
	done := make(chan error, 1)
	go func() { done <- RunWorker(context.Background(), input, output, io.Discard) }()
	if err := bootstrap.WriteWorkerCommand(inputWriter, bootstrap.WorkerCommand{Version: 1, Type: "DRAIN", OperationID: "uninitialized", RemainingNS: int64(time.Second)}); err != nil {
		t.Fatal(err)
	}
	event, err := bootstrap.ReadWorkerEvent(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != "FAILED" || event.OperationID != "" || event.Failure == nil {
		t.Fatalf("pre-init command did not fail closed: %+v", event)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pre-init DRAIN accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("worker retained uninitialized control read")
	}
}

func TestGvxWorkerCancellationClosesInitializationRead(t *testing.T) {
	input, inputWriter := io.Pipe()
	outputReader, output := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	defer output.Close()
	defer outputReader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWorker(ctx, input, output, io.Discard) }()
	cancel()
	event, err := bootstrap.ReadWorkerEvent(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != "FAILED" {
		t.Fatal("canceled initialization did not report failure")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled initialization succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock actual control pipe")
	}
}
