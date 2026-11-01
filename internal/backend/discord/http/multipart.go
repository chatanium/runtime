package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
)

// Choose framing only after the caller has immutable upload sources. It is
// never derived from or disclosed before those bytes are fixed.
func newMultipartBoundary() (string, error) {
	var entropy [24]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		return "", ErrTransport
	}
	return "chatanium-" + hex.EncodeToString(entropy[:]), nil
}

const copyBufferBytes = 32 * 1024

type bodyCounter struct{ size, limit int64 }

func (c *bodyCounter) add(size int64) error {
	if size < 0 || size > c.limit-c.size {
		return ErrBodyTooLarge
	}
	c.size += size
	return nil
}

func (p *preparedRequest) multipartLength(limit int64) (int64, error) {
	counter := &bodyCounter{limit: limit}
	for i, header := range p.parts {
		if err := counter.add(int64(len(header))); err != nil {
			return 0, err
		}
		var size int64
		if i == 0 {
			size = int64(len(p.json))
		} else {
			size = p.files[i-1].Size
		}
		if err := counter.add(size); err != nil {
			return 0, err
		}
	}
	if err := counter.add(int64(len(p.closing))); err != nil {
		return 0, err
	}
	return counter.size, nil
}

type ownedReader struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (r *ownedReader) Close() error { r.once.Do(func() { r.err = r.ReadCloser.Close() }); return r.err }

type multipartProducer struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cancelHTTP context.CancelFunc
	reader     *io.PipeReader
	writer     *io.PipeWriter
	mu         sync.Mutex
	current    *ownedReader
	abortOnce  sync.Once
	done       chan struct{}
	err        error
	stop       func() bool
}

func (p *preparedRequest) open(ctx context.Context, cancelHTTP context.CancelFunc) (io.ReadCloser, *multipartProducer) {
	if len(p.files) == 0 {
		return p.jsonBody(), nil
	}
	work, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	producer := &multipartProducer{ctx: work, cancel: cancel, cancelHTTP: cancelHTTP, reader: reader, writer: writer, done: make(chan struct{})}
	producer.stop = context.AfterFunc(ctx, producer.abort)
	go func() {
		err := producer.write(p)
		producer.err = err
		_ = writer.CloseWithError(err)
		// Only a source failure cancels HTTP. Pipe errors instead originate
		// from HTTP stopping its body read or from cleanup; canceling HTTP
		// for those would hide a causal TLS/network error as context.Canceled.
		if err == ErrFile || err == ErrInvalidRequest {
			producer.cancelHTTP()
		}
		close(producer.done)
	}()
	return reader, producer
}

func (p *multipartProducer) abort() {
	p.abortOnce.Do(func() {
		p.cancel()
		_ = p.reader.CloseWithError(context.Canceled)
		_ = p.writer.CloseWithError(context.Canceled)
		p.mu.Lock()
		reader := p.current
		p.mu.Unlock()
		if reader != nil {
			_ = reader.Close()
		}
	})
}

func (p *multipartProducer) join() error {
	<-p.done
	p.stop()
	return p.err
}

func (p *multipartProducer) write(body *preparedRequest) error {
	buffer := make([]byte, copyBufferBytes)
	for i, header := range body.parts {
		if p.ctx.Err() != nil {
			return p.ctx.Err()
		}
		if _, err := p.writer.Write(header); err != nil {
			return err
		}
		if i == 0 {
			if _, err := p.writer.Write(body.json); err != nil {
				return err
			}
			continue
		}
		file := body.files[i-1]
		opened, err := file.Open(p.ctx)
		if err != nil {
			if opened != nil {
				_ = opened.Close()
			}
			if p.ctx.Err() != nil {
				return p.ctx.Err()
			}
			return ErrFile
		}
		if opened == nil {
			return ErrFile
		}
		reader := &ownedReader{ReadCloser: opened}
		p.mu.Lock()
		p.current = reader
		canceled := p.ctx.Err() != nil
		p.mu.Unlock()
		if canceled {
			_ = reader.Close()
			return p.ctx.Err()
		}
		err = copyExact(p.writer, reader, file.Size, buffer, p.ctx)
		closeErr := reader.Close()
		p.mu.Lock()
		p.current = nil
		p.mu.Unlock()
		if err != nil {
			return err
		}
		if closeErr != nil {
			if p.ctx.Err() != nil {
				return p.ctx.Err()
			}
			return ErrFile
		}
	}
	if _, err := p.writer.Write(body.closing); err != nil {
		return err
	}
	return nil
}

// No io.Copy fast path is used: the source's WriterTo must not allocate an
// unbounded buffer or bypass the exact-size and cancellation boundary.
func copyExact(dst io.Writer, src io.Reader, size int64, buffer []byte, ctx context.Context) error {
	remaining := size
	for remaining > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:int(remaining)]
		}
		n, err := src.Read(chunk)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if n < 0 || n > len(chunk) {
			return ErrFile
		}
		if n > 0 {
			written, writeErr := dst.Write(chunk[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			remaining -= int64(n)
		}
		if err != nil {
			if err == io.EOF && remaining == 0 {
				break
			}
			return ErrFile
		}
		if n == 0 {
			return ErrFile
		}
	}
	// Detect an immutable source whose declared size is incorrect, including
	// an allegedly empty source. Never read the file during size calculation.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var extra [1]byte
	n, err := src.Read(extra[:])
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n != 0 || err != io.EOF {
		return ErrFile
	}
	return nil
}
