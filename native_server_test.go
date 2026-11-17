package tang

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestNativeReadFragmentedRequest(t *testing.T) {
	body := strings.Repeat("x", 9000)
	input := fmt.Sprintf("POST /rec/test HTTP/1.1\r\nHost: example\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	wire, err := readNativeRequest(iotest.OneByteReader(strings.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}
	assertNativeRequest(t, wire, body)
}

func assertNativeRequest(t *testing.T, wire []byte, wantBody string) {
	t.Helper()
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Body.Close()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != wantBody || request.ContentLength != int64(len(wantBody)) {
		t.Fatalf("body length = %d, Content-Length = %d; want %d", len(body), request.ContentLength, len(wantBody))
	}
	if len(request.TransferEncoding) != 0 || !request.Close {
		t.Fatal("forwarded request must use Content-Length and close the connection")
	}
}

func TestNativeReadRequestLimits(t *testing.T) {
	body := strings.Repeat("x", nativeMaxBodySize)
	prefix := "GET /adv HTTP/1.1\r\nHost: example\r\nX-Pad: "
	exactHeader := prefix + strings.Repeat("x", nativeMaxHeaderSize-len(prefix)-4) + "\r\n\r\n"
	cases := []struct {
		name  string
		input string
		body  string
	}{
		{"empty body", "GET /adv HTTP/1.1\r\nHost: example\r\n\r\n", ""},
		{"exact header cap", exactHeader, ""},
		{"exact body cap", fmt.Sprintf("POST /rec/test HTTP/1.1\r\nHost: example\r\nContent-Length: %d\r\n\r\n%s", len(body), body), body},
		{"chunked body", fmt.Sprintf("POST /rec/test HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body), body},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := readNativeRequest(strings.NewReader(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			assertNativeRequest(t, wire, tc.body)
		})
	}
}

func TestNativeRejectInvalidRequests(t *testing.T) {
	oversized := strings.Repeat("x", nativeMaxBodySize+1)
	cases := []struct {
		name  string
		input string
		want  error
	}{
		{"large header", "GET /adv HTTP/1.1\r\nX-Pad: " + strings.Repeat("x", nativeMaxHeaderSize) + "\r\n\r\n", errNativeHeaderTooLarge},
		{"unterminated header", "GET /adv HTTP/1.1\r\nHost: example\r\n", nil},
		{"invalid header", "GET /adv HTTP/1.1\r\nBad Header: x\r\n\r\n", nil},
		{"invalid header value", "GET /adv HTTP/1.1\r\nX-Test: x\x01y\r\n\r\n", nil},
		{"negative length", "POST /rec/test HTTP/1.1\r\nContent-Length: -1\r\n\r\n", nil},
		{"conflicting lengths", "POST /rec/test HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx", nil},
		{"truncated body", "POST /rec/test HTTP/1.1\r\nContent-Length: 4\r\n\r\nxx", nil},
		{"oversized declared body", fmt.Sprintf("POST /rec/test HTTP/1.1\r\nContent-Length: %d\r\n\r\n", nativeMaxBodySize+1), errNativeBodyTooLarge},
		{"oversized chunked body", fmt.Sprintf("POST /rec/test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(oversized), oversized), errNativeBodyTooLarge},
		{"invalid chunk", "POST /rec/test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\ninvalid\r\n", nil},
		{"truncated chunk", "POST /rec/test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readNativeRequest(strings.NewReader(tc.input)); err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("error = %v, want rejection (%v)", err, tc.want)
			}
		})
	}
}

func TestNativeBoundChunkFraming(t *testing.T) {
	input := "POST /rec/test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
		strings.Repeat("1;"+strings.Repeat("x", 1024)+"\r\nx\r\n", 200) + "0\r\n\r\n"
	reader := strings.NewReader(input)
	if _, err := readNativeRequest(reader); err == nil {
		t.Fatal("expected rejection of excessive chunk framing")
	}
	if consumed := len(input) - reader.Len(); consumed > nativeMaxWireSize {
		t.Fatalf("read %d wire bytes, limit is %d", consumed, nativeMaxWireSize)
	}
}

// This listener supplies net.Pipe connections without opening real sockets.
type nativeTestListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func (l *nativeTestListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.connections:
		return conn, nil
	}
}

func (l *nativeTestListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *nativeTestListener) Addr() net.Addr { return &net.TCPAddr{} }

func newNativeTestServer(t *testing.T, timeout time.Duration, run func(context.Context, []byte, io.Writer) error) (*NativeServer, *nativeTestListener) {
	t.Helper()
	listener := &nativeTestListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	s := newNativeServer("unused", "unused", listener)
	s.requestTimeout = timeout
	s.run = run
	go s.Serve()
	t.Cleanup(s.Stop)
	return s, listener
}

func nativeTestConnect(t *testing.T, listener *nativeTestListener) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case listener.connections <- server:
	case <-time.After(3 * time.Second):
		_ = server.Close()
		t.Fatal("server did not accept connection")
	}
	return client
}

func TestNativeStopIdleConnection(t *testing.T) {
	s, listener := newNativeTestServer(t, time.Minute, func(context.Context, []byte, io.Writer) error {
		t.Error("idle connection must not invoke child")
		return nil
	})
	client := nativeTestConnect(t, listener)
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not unblock idle connection")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("active socket was not closed")
	}
	s.Stop()
}

func TestNativeStopCancelsAndWaitsForChild(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseChild := func() { releaseOnce.Do(func() { close(release) }) }
	s, listener := newNativeTestServer(t, time.Minute, func(ctx context.Context, request []byte, output io.Writer) error {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	})
	// Release before the server cleanup, including on an assertion failure.
	t.Cleanup(releaseChild)
	client := nativeTestConnect(t, listener)
	if _, err := io.WriteString(client, "GET /adv HTTP/1.1\r\nHost: example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("child did not start")
	}
	stopped := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); s.Stop() }()
		}
		wg.Wait()
		close(stopped)
	}()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not cancel child")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before child cleanup")
	default:
	}
	releaseChild()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not wait successfully for child cleanup")
	}
	select {
	case <-s.done:
	default:
		t.Fatal("serving goroutine has not exited")
	}
}

func TestNativeRequestDeadline(t *testing.T) {
	for _, partial := range []string{"", "GET /adv HTTP/1.1\r\n", "POST /rec/test HTTP/1.1\r\nContent-Length: 4\r\n\r\nx"} {
		t.Run(fmt.Sprintf("partial_%d", len(partial)), func(t *testing.T) {
			_, listener := newNativeTestServer(t, 100*time.Millisecond, func(context.Context, []byte, io.Writer) error {
				t.Error("incomplete request must not invoke child")
				return nil
			})
			client := nativeTestConnect(t, listener)
			if partial != "" {
				if _, err := io.WriteString(client, partial); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("expected closed connection after server deadline, got %v", err)
			}
			// A serial server must continue accepting after timing out an idle peer.
			_ = nativeTestConnect(t, listener)
		})
	}
}

func TestNativeChildDeadline(t *testing.T) {
	exited := make(chan struct{})
	_, listener := newNativeTestServer(t, 100*time.Millisecond, func(ctx context.Context, _ []byte, _ io.Writer) error {
		<-ctx.Done()
		defer close(exited)
		return ctx.Err()
	})
	client := nativeTestConnect(t, listener)
	if _, err := io.WriteString(client, "GET /adv HTTP/1.1\r\nHost: example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("child did not receive request deadline")
	}
}

func TestNativeStopBeforeServe(t *testing.T) {
	listener := &nativeTestListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	s := newNativeServer("unused", "unused", listener)
	s.Stop()
	s.Serve()
	s.Stop()
	select {
	case <-listener.closed:
	default:
		t.Fatal("listener was not closed")
	}
}

// An inert subprocess fixture exercises the real CommandContext path without
// tangd or key files. Only the test binary is launched when tests are run.
func TestNativeCommandFixture(t *testing.T) {
	if os.Getenv("TANG_GO_NATIVE_CHILD_FIXTURE") != "1" {
		return
	}
	if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
		os.Exit(2)
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}

func TestNativeCommandCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TANG_GO_NATIVE_CHILD_FIXTURE", "1")
	s := &NativeServer{tangdPath: executable, KeysDir: "-test.run=^TestNativeCommandFixture$"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	finished := make(chan error, 1)
	request := []byte("inert child input")
	go func() { finished <- s.runCommand(ctx, request, writer) }()
	// Closing the pipe on timeout also bounds the fixture's output read.
	stop := context.AfterFunc(ctx, func() { _ = reader.Close() })
	defer stop()
	output := make([]byte, len(request))
	if _, err := io.ReadFull(reader, output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, request) {
		t.Fatal("child did not receive complete stdin")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled child unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled child was not reaped")
	}
}
