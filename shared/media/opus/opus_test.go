package opus

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testPage(sequence uint32, flags byte, segments []byte, data []byte) []byte {
	page := make([]byte, 27+len(segments)+len(data))
	copy(page, "OggS")
	page[5] = flags
	binary.LittleEndian.PutUint32(page[14:18], 42)
	binary.LittleEndian.PutUint32(page[18:22], sequence)
	page[26] = byte(len(segments))
	copy(page[27:], segments)
	copy(page[27+len(segments):], data)
	var crc uint32
	for _, b := range page {
		crc = crc<<8 ^ oggCRC[byte(crc>>24)^b]
	}
	binary.LittleEndian.PutUint32(page[22:26], crc)
	return page
}

func testHeaders() []byte {
	head := make([]byte, 19)
	copy(head, "OpusHead")
	head[8], head[9] = 1, 2
	binary.LittleEndian.PutUint32(head[12:16], 48000)
	tags := make([]byte, 16)
	copy(tags, "OpusTags")
	return append(testPage(0, 2, []byte{19}, head), testPage(1, 0, []byte{16}, tags)...)
}

func TestOggContinuedPacket(t *testing.T) {
	packet := bytes.Repeat([]byte{0x78}, 300)
	input := testHeaders()
	input = append(input, testPage(2, 0, []byte{255}, packet[:255])...)
	input = append(input, testPage(3, 5, []byte{45, 2}, append(append([]byte{}, packet[255:]...), 0xf8, 0xff))...)
	r := &oggReader{r: bytes.NewReader(input)}
	got, err := r.next()
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("continued packet = %x, %v", got, err)
	}
	got, err = r.next()
	if err != nil || !bytes.Equal(got, []byte{0xf8, 0xff}) {
		t.Fatalf("following packet = %x, %v", got, err)
	}
	if _, err := r.next(); err != io.EOF {
		t.Fatalf("EOS = %v", err)
	}
}

func TestOggContinuedTagsAndExactLacing(t *testing.T) {
	head := make([]byte, 19)
	copy(head, "OpusHead")
	head[8], head[9] = 1, 2
	binary.LittleEndian.PutUint32(head[12:16], 48000)
	tags := make([]byte, 300)
	copy(tags, "OpusTags")
	binary.LittleEndian.PutUint32(tags[8:12], 284) // Vendor consumes the rest, except the comment count.
	packet := bytes.Repeat([]byte{0x78}, 255)
	input := testPage(0, 2, []byte{19}, head)
	input = append(input, testPage(1, 0, []byte{255}, tags[:255])...)
	input = append(input, testPage(2, 1, []byte{45}, tags[255:])...)
	input = append(input, testPage(3, 4, []byte{255, 0}, packet)...)
	r := &oggReader{r: bytes.NewReader(input)}
	got, err := r.next()
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("packet following continued tags = %x, %v", got, err)
	}
	if _, err := r.next(); err != io.EOF {
		t.Fatalf("EOS = %v", err)
	}
}

func TestOggRejectsMalformedStreams(t *testing.T) {
	valid := append(testHeaders(), testPage(2, 4, []byte{2}, []byte{0xf8, 0xff})...)
	badCRC := append([]byte{}, valid...)
	badCRC[len(badCRC)-1] ^= 1
	cases := map[string][]byte{
		"checksum":             badCRC,
		"missing EOS":          append(testHeaders(), testPage(2, 0, []byte{2}, []byte{0xf8, 0xff})...),
		"missing continuation": append(testHeaders(), testPage(2, 5, []byte{2}, []byte{0xf8, 0xff})...),
		"unfinished packet":    append(testHeaders(), testPage(2, 4, []byte{255}, bytes.Repeat([]byte{1}, 255))...),
		"truncated data":       valid[:len(valid)-1],
		"sequence gap":         append(testHeaders(), testPage(4, 4, []byte{2}, []byte{0xf8, 0xff})...),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			r := &oggReader{r: bytes.NewReader(input)}
			for range 3 {
				_, err := r.next()
				if err != nil {
					if err == io.EOF {
						t.Fatal("malformed stream returned clean EOF")
					}
					return
				}
			}
			t.Fatal("malformed stream accepted")
		})
	}
}

func TestDCAFrameBoundsAndTruncation(t *testing.T) {
	for _, input := range [][]byte{
		{0, 0}, {0xff, 0xff}, {2, 0, 1},
		append([]byte("DCA1"), 0xff, 0xff, 0xff, 0x7f),
	} {
		if _, err := NewDecoder(bytes.NewReader(input)).OpusFrame(context.Background()); err == nil || err == io.EOF {
			t.Fatalf("invalid input %x returned %v", input, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewDecoder(bytes.NewReader(nil)).OpusFrame(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read = %v", err)
	}
}

func TestDCAOldMetadataAndRawFrames(t *testing.T) {
	metadata := []byte(`{"opus":{"channels":2,"sample_rate":48000}}`)
	old := append([]byte("DCA1"), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(old[4:8], uint32(len(metadata)))
	old = append(old, metadata...)
	raw := []byte{2, 0, 0xf8, 0xff}
	for _, input := range [][]byte{raw, append(old, raw...)} {
		r := NewDecoder(bytes.NewReader(input))
		got, err := r.OpusFrame(context.Background())
		if err != nil || !bytes.Equal(got, raw[2:]) {
			t.Fatalf("frame = %x, %v", got, err)
		}
		if _, err := r.OpusFrame(context.Background()); err != io.EOF {
			t.Fatalf("frame EOF = %v", err)
		}
	}
}

func TestOggConsumerLimits(t *testing.T) {
	packet := bytes.Repeat([]byte{0x78}, 300)
	input := append(testHeaders(), testPage(2, 4, []byte{255, 45}, packet)...)
	r := &oggReader{r: bytes.NewReader(input), maxPacketBytes: 299}
	if _, err := r.next(); err == nil || cap(r.packet) > 299 {
		t.Fatalf("packet bound: error=%v capacity=%d", err, cap(r.packet))
	}
	r = &oggReader{r: bytes.NewReader(testHeaders()), maxMetadataBytes: 15}
	if _, err := r.next(); err == nil || cap(r.packet) > 19 {
		t.Fatalf("metadata bound: error=%v capacity=%d", err, cap(r.packet))
	}
	// A second logical stream or arbitrary bytes must not be accepted after EOS.
	input = append(testHeaders(), testPage(2, 4, []byte{2}, []byte{0xf8, 0xff})...)
	input = append(input, 0)
	r = &oggReader{r: bytes.NewReader(input)}
	if _, err := r.next(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.next(); err == nil || err == io.EOF {
		t.Fatalf("trailing output: %v", err)
	}
}

func TestOpusPacketFramingAndDuration(t *testing.T) {
	for _, packet := range [][]byte{
		{0xf8, 0xff, 0xfe},                // One 20ms CELT frame.
		{0xf1, 1, 2},                      // Two equal 10ms CELT frames.
		{0xf2, 1, 1, 2},                   // Two VBR 10ms frames.
		{0xe3, 8, 1, 2, 3, 4, 5, 6, 7, 8}, // Eight 2.5ms frames.
	} {
		if err := validatePacket(packet); err != nil {
			t.Fatalf("valid framing %x: %v", packet, err)
		}
	}
	for _, packet := range [][]byte{
		nil, {0xf0, 1}, {0xf9, 1, 2}, // Empty, 10ms and 40ms.
		{0xf1, 1}, {0xf2, 252}, {0xf2, 9, 1}, // Bad CBR/VBR sizes.
		{0xf3}, {0xf3, 0}, {0xf3, 0x42, 255}, // Missing count/padding.
	} {
		if err := validatePacket(packet); err == nil {
			t.Fatalf("invalid framing accepted: %x", packet)
		}
	}
}

func TestOggHeaderAndCommentValidation(t *testing.T) {
	head := make([]byte, 19)
	copy(head, "OpusHead")
	head[8], head[9] = 1, 2
	binary.LittleEndian.PutUint32(head[12:16], 44100)
	r := &oggReader{r: bytes.NewReader(testPage(0, 2, []byte{19}, head))}
	if _, err := r.next(); err == nil {
		t.Fatal("accepted non-48kHz header")
	}
	for _, size := range []uint32{1, ^uint32(0)} {
		tags := make([]byte, 16)
		copy(tags, "OpusTags")
		binary.LittleEndian.PutUint32(tags[8:12], size)
		if err := validateTags(tags); err == nil {
			t.Fatalf("accepted truncated vendor %d", size)
		}
		binary.LittleEndian.PutUint32(tags[8:12], 0)
		binary.LittleEndian.PutUint32(tags[12:16], size)
		if err := validateTags(tags); err == nil {
			t.Fatalf("accepted truncated comment count %d", size)
		}
	}
}

func encoderFixture(t *testing.T, output []byte, body string) (EncodeOptions, string) {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	fixture := filepath.Join(dir, "output")
	executable := filepath.Join(dir, "encoder")
	if err := os.WriteFile(input, []byte("local input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, output, 0600); err != nil {
		t.Fatal(err)
	}
	if body == "" {
		body = "exec /bin/cat \"$OPUS_ENCODER_FIXTURE\"\n"
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	prelude := "#!/bin/sh\nOPUS_ENCODER_FIXTURE=" + quote(fixture) + "\n" +
		"OPUS_ENCODER_PIDS=" + quote(filepath.Join(dir, "pids")) + "\n"
	if err := os.WriteFile(executable, []byte(prelude+body), 0700); err != nil {
		t.Fatal(err)
	}
	return EncodeOptions{
		Executable: executable, BitrateKbps: 64, MaxInputBytes: 1024,
		MaxOutputBytes: 4096, MaxFrames: 10, MaxPacketBytes: 1275,
		MaxDiagnosticBytes: 128, Timeout: time.Second,
	}, input
}

func TestEncodeCompleteShortArtifactAndCallerOwnership(t *testing.T) {
	output := append(testHeaders(), testPage(2, 4, []byte{3}, []byte{0xf8, 0xff, 0xfe})...)
	opts, input := encoderFixture(t, output, "")
	opts.MaxOutputBytes = int64(len(output)) // Exact raw-output boundary succeeds.
	dst, err := os.CreateTemp(t.TempDir(), "owned-artifact-")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	result, err := Encode(context.Background(), input, dst, opts)
	if err != nil || result.Frames != 1 || result.Bytes != 5 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if err := dst.Sync(); err != nil {
		t.Fatalf("encoder closed caller file: %v", err)
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	packet, err := NewDecoder(dst).OpusFrame(context.Background())
	if err != nil || !bytes.Equal(packet, []byte{0xf8, 0xff, 0xfe}) {
		t.Fatalf("artifact packet %x: %v", packet, err)
	}
}

func TestEncodeRejectsIncompleteAndBoundedOutput(t *testing.T) {
	single := append(testHeaders(), testPage(2, 4, []byte{3}, []byte{0xf8, 0xff, 0xfe})...)
	two := append(testHeaders(), testPage(2, 4, []byte{3, 3}, []byte{0xf8, 0xff, 0xfe, 0xf8, 0xff, 0xfe})...)
	for _, name := range []string{"empty", "truncated", "process failure", "frames", "packets", "stdout", "diagnostics"} {
		t.Run(name, func(t *testing.T) {
			output, body := single, ""
			switch name {
			case "empty":
				output = append(testHeaders(), testPage(2, 4, nil, nil)...)
			case "truncated":
				output = single[:len(single)-1]
			case "process failure":
				body = "/bin/cat \"$OPUS_ENCODER_FIXTURE\"\nexit 7\n"
			case "frames":
				output = two
			case "diagnostics":
				body = "printf 'too much stderr' >&2\nexec /bin/cat \"$OPUS_ENCODER_FIXTURE\"\n"
			}
			opts, input := encoderFixture(t, output, body)
			switch name {
			case "frames":
				opts.MaxFrames = 1
			case "packets":
				opts.MaxPacketBytes = 2
			case "stdout":
				opts.MaxOutputBytes = int64(len(single) - 1)
			case "diagnostics":
				opts.MaxDiagnosticBytes = 3
			}
			var dst bytes.Buffer
			result, err := Encode(context.Background(), input, &dst, opts)
			if err == nil || result != (EncodeResult{}) {
				t.Fatalf("partial success %+v: %v", result, err)
			}
			if name == "empty" && !errors.Is(err, ErrEmptyAudio) {
				t.Fatalf("empty result: %v", err)
			}
			if name == "diagnostics" && !strings.Contains(err.Error(), "diagnostic byte limit exceeded") {
				t.Fatalf("diagnostic overflow: %v", err)
			}
		})
	}
}

type failedEncoderWriter struct{ err error }

func (w failedEncoderWriter) Write([]byte) (int, error) { return 0, w.err }

func TestEncodePreservesDestinationFailure(t *testing.T) {
	output := append(testHeaders(), testPage(2, 4, []byte{3}, []byte{0xf8, 0xff, 0xfe})...)
	opts, input := encoderFixture(t, output, "")
	cause := errors.New("destination quota exceeded")
	if _, err := Encode(context.Background(), input, failedEncoderWriter{cause}, opts); !errors.Is(err, cause) {
		t.Fatalf("lost destination failure: %v", err)
	}
}

func TestEncodeRejectsUnboundedOptionsAndNonlocalInputs(t *testing.T) {
	opts, input := encoderFixture(t, nil, "")
	for _, mutate := range []func(*EncodeOptions){
		func(o *EncodeOptions) { o.Executable = "ffmpeg" },
		func(o *EncodeOptions) { o.BitrateKbps = 0 },
		func(o *EncodeOptions) { o.MaxInputBytes = 0 },
		func(o *EncodeOptions) { o.MaxOutputBytes = 0 },
		func(o *EncodeOptions) { o.MaxFrames = 0 },
		func(o *EncodeOptions) { o.MaxPacketBytes = 0 },
		func(o *EncodeOptions) { o.MaxDiagnosticBytes = 0 },
		func(o *EncodeOptions) { o.Timeout = 0 },
	} {
		invalid := opts
		mutate(&invalid)
		if _, err := Encode(context.Background(), input, io.Discard, invalid); err == nil {
			t.Fatalf("accepted %+v", invalid)
		}
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(input, symlink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{symlink, fifo, filepath.Dir(input), "https://example.invalid/audio"} {
		if _, err := Encode(context.Background(), path, io.Discard, opts); err == nil {
			t.Fatalf("accepted input %s", path)
		}
	}
	opts.MaxInputBytes = 1
	if _, err := Encode(context.Background(), input, io.Discard, opts); err == nil {
		t.Fatal("accepted oversized input")
	}
	if err := os.Truncate(input, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Encode(context.Background(), input, io.Discard, opts); !errors.Is(err, ErrEmptyAudio) {
		t.Fatalf("empty local input: %v", err)
	}
}

func TestEncodeTimeoutKillsGroupAndReaps(t *testing.T) {
	opts, input := encoderFixture(t, nil, "/bin/sleep 30 &\nwait\n")
	opts.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := Encode(context.Background(), input, io.Discard, opts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout cause: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("encoder was not reaped promptly: %s", elapsed)
	}
}

func TestDiagnosticLimitAndSanitization(t *testing.T) {
	killed := 0
	b := diagnosticBuffer{limit: 4, overflow: func() { killed++ }}
	if n, err := b.Write([]byte("a\x1b\nb")); n != 4 || err != nil {
		t.Fatalf("write %d: %v", n, err)
	}
	if string(b.data) != "a??b" || b.err != nil {
		t.Fatalf("diagnostic %q: %v", b.data, b.err)
	}
	b.Write([]byte("overflow"))
	b.Write([]byte("again"))
	if b.err == nil || killed != 1 || len(b.data) != 4 || cap(b.data) > 4 {
		t.Fatalf("overflow %+v, killed=%d", b, killed)
	}
}

func TestEncodeChildWritesStayInOwnedInputDirectory(t *testing.T) {
	output := append(testHeaders(), testPage(2, 4, []byte{3}, []byte{0xf8, 0xff, 0xfe})...)
	opts, input := encoderFixture(t, output,
		"temporary=$(/usr/bin/mktemp) || exit 11\n"+
			"printf '%s\\n' \"$temporary\" >> \"$OPUS_ENCODER_FIXTURE.created-paths\"\n"+
			"printf temp > \"$temporary\" || exit 12\n"+
			"home=$(/usr/bin/mktemp \"$HOME/encoder-home.XXXXXXXX\") || exit 13\n"+
			"printf '%s\\n' \"$home\" >> \"$OPUS_ENCODER_FIXTURE.created-paths\"\n"+
			"printf home > \"$home\" || exit 14\n"+
			"relative=$(/usr/bin/mktemp ./encoder-relative.XXXXXXXX) || exit 15\n"+
			"relative=\"$(pwd -P)/$relative\"\n"+
			"printf '%s\\n' \"$relative\" >> \"$OPUS_ENCODER_FIXTURE.created-paths\"\n"+
			"printf relative > \"$relative\" || exit 16\n"+
			"exec /bin/cat \"$OPUS_ENCODER_FIXTURE\"\n")
	dir := filepath.Dir(input)
	createdPaths := filepath.Join(dir, "output.created-paths")
	// Also remove fixture-created files if a regression placed them outside
	// the owned directory, rather than leaving stray test files behind.
	t.Cleanup(func() {
		if data, err := os.ReadFile(createdPaths); err == nil {
			for _, path := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				if path != "" {
					_ = os.Remove(path)
				}
			}
		}
	})
	if _, err := Encode(context.Background(), input, io.Discard, opts); err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(createdPaths)
	if err != nil {
		t.Fatal(err)
	}
	paths := strings.Split(strings.TrimSuffix(string(recorded), "\n"), "\n")
	if len(paths) != 3 {
		t.Fatalf("child created %d files, want temp, home and relative files", len(paths))
	}
	for i, path := range paths {
		if filepath.Dir(filepath.Clean(path)) != dir {
			t.Fatalf("child write escaped owned input directory: %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"temp", "home", "relative"}[i]; string(data) != want {
			t.Fatalf("child file %q contains %q, want %q", path, data, want)
		}
	}
	// Directory cleanup belongs to the caller, after the encoder has exited.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned encoder work directory was not reclaimed: %v", err)
	}
}

func TestEncodeCancellationStopsDescendantsAndReapsLeader(t *testing.T) {
	opts, input := encoderFixture(t, nil, "/bin/sleep 30 &\nprintf '%s %s' \"$$\" \"$!\" > \"$OPUS_ENCODER_PIDS\"\nwait\n")
	opts.Timeout = 3 * time.Second
	pidsPath := filepath.Join(filepath.Dir(input), "pids")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Encode(ctx, input, io.Discard, opts); done <- err }()
	var pids []string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidsPath)
		if err == nil {
			pids = strings.Fields(string(data))
			if len(pids) == 2 {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if len(pids) != 2 {
		cancel()
		<-done
		t.Fatal("encoder fixture never started its child")
	}
	leader, err := strconv.Atoi(pids[0])
	if err != nil {
		t.Fatal(err)
	}
	child, err := strconv.Atoi(pids[1])
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("encoder cancellation failed to return")
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(leader, &status, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("encoder leader was not reaped: %v", err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child), "stat"))
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		// A killed orphan may briefly await the container init's reap. It must
		// no longer run or hold encoder descriptors after Encode returns.
		close := strings.LastIndexByte(string(data), ')')
		if close >= 0 && len(data) > close+2 && (data[close+2] == 'Z' || data[close+2] == 'X') {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("encoder descendant %d remains alive", child)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestEncodeRejectsInputMutation(t *testing.T) {
	output := append(testHeaders(), testPage(2, 4, []byte{3}, []byte{0xf8, 0xff, 0xfe})...)
	opts, input := encoderFixture(t, output, "printf 'growth' >> /proc/self/fd/3\nexec /bin/cat \"$OPUS_ENCODER_FIXTURE\"\n")
	result, err := Encode(context.Background(), input, io.Discard, opts)
	if err == nil || !strings.Contains(err.Error(), "input changed") || result != (EncodeResult{}) {
		t.Fatalf("mutated input published: %+v, %v", result, err)
	}
}

func TestEncodeArtifactLimitIncludesLengthPrefixes(t *testing.T) {
	// Many tiny packets make the artifact's per-packet length prefixes larger
	// than Ogg's lacing overhead, exercising the independent artifact byte cap.
	segments := bytes.Repeat([]byte{3}, 200)
	packets := bytes.Repeat([]byte{0xf8, 0xff, 0xfe}, 200)
	output := append(testHeaders(), testPage(2, 4, segments, packets)...)
	opts, input := encoderFixture(t, output, "")
	opts.MaxFrames = 200
	opts.MaxOutputBytes = int64(len(output))
	var dst bytes.Buffer
	result, err := Encode(context.Background(), input, &dst, opts)
	if err == nil || !strings.Contains(err.Error(), "artifact byte limit exceeded") || result != (EncodeResult{}) {
		t.Fatalf("artifact prefix bound: %+v, %v", result, err)
	}
	if int64(dst.Len()) > opts.MaxOutputBytes {
		t.Fatalf("wrote %d bytes above %d", dst.Len(), opts.MaxOutputBytes)
	}
}
