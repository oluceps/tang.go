package tang

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	nativeMaxHeaderSize = 16 * 1024
	nativeMaxBodySize   = 64 * 1024
	// Also bound chunk framing and trailers, not just the decoded body.
	nativeMaxWireSize    = 2 * (nativeMaxHeaderSize + nativeMaxBodySize)
	nativeRequestTimeout = 30 * time.Second
)

var (
	errNativeHeaderTooLarge = errors.New("request headers too large")
	errNativeBodyTooLarge   = errors.New("request body too large")
)

// NativeServer is a server implementation that redirects requests to the native "tangd" binary.
// This code is useful for tests or when one needs a wrapper around tangd binary.
// Requests are served serially, with a deadline covering reads, the child, and writes.
// This bounds the server to one active connection and one child at a time.
type NativeServer struct {
	KeysDir string
	Port    int

	tangdPath      string
	listener       net.Listener
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	requestTimeout time.Duration
	run            func(context.Context, []byte, io.Writer) error

	mu       sync.Mutex
	started  bool
	stopping bool
	active   net.Conn
}

// NewNativeServer creates instance of a native Tang server.
func NewNativeServer(keysDir string, port int) (*NativeServer, error) {
	// Discover an executable before acquiring the listening socket.
	tangdPath, err := findTangdExecutable()
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	s := newNativeServer(keysDir, tangdPath, l)
	s.Port = l.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return s, nil
}

func findTangdExecutable() (string, error) {
	for _, location := range []string{
		"/usr/lib/tangd",
		"/usr/libexec/tangd",
		"/usr/lib/x86_64-linux-gnu/tangd",
	} {
		if executable, err := exec.LookPath(location); err == nil {
			return executable, nil
		}
	}
	return "", errors.New("unable to find tangd binary")
}

// newNativeServer separates setup from serving so tests need no native executable.
func newNativeServer(keysDir, tangdPath string, listener net.Listener) *NativeServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &NativeServer{
		KeysDir:        keysDir,
		tangdPath:      tangdPath,
		listener:       listener,
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan struct{}),
		requestTimeout: nativeRequestTimeout,
	}
	s.run = s.runCommand
	return s
}

// Stop closes the listener and active socket, cancels the child, and waits for
// serving to finish. It is safe to call repeatedly or concurrently.
func (s *NativeServer) Stop() {
	s.mu.Lock()
	first := !s.stopping
	s.stopping = true
	active := s.active
	s.mu.Unlock()
	if first {
		s.cancel()
		_ = s.listener.Close()
		if active != nil {
			_ = active.Close()
		}
	}
	// Serve also handles Stop arriving before its goroutine is scheduled.
	// Calling it here makes shutdown safe even before serving has started.
	s.Serve()
	<-s.done
}

// Serve serves HTTP requests. Only the first call runs the accept loop.
func (s *NativeServer) Serve() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	stopping := s.stopping
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		s.cancel()
		_ = s.listener.Close()
		close(s.done)
	}()
	if stopping {
		return
	}

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && s.ctx.Err() == nil {
				log.Println("accept error", err)
			}
			return
		}
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.active = conn
		s.mu.Unlock()

		s.handleConnection(conn)
		_ = conn.Close()
		s.mu.Lock()
		s.active = nil
		s.mu.Unlock()
	}
}

func (s *NativeServer) handleConnection(conn net.Conn) {
	ctx, cancel := context.WithTimeout(s.ctx, s.requestTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return
	}

	request, err := readNativeRequest(conn)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errNativeHeaderTooLarge) {
			status = http.StatusRequestHeaderFieldsTooLarge
		} else if errors.Is(err, errNativeBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		// Do not echo or log request data, including malformed input.
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	if err := s.run(ctx, request, conn); err != nil && ctx.Err() == nil {
		log.Println("tangd failed", err)
	}
}

func (s *NativeServer) runCommand(ctx context.Context, request []byte, output io.Writer) error {
	cmd := exec.CommandContext(ctx, s.tangdPath, s.KeysDir)
	cmd.Stdin = bytes.NewReader(request)
	cmd.Stdout = output
	// Bound waiting on inherited child pipes as well as the direct child.
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

// readNativeRequest buffers exactly one complete, bounded HTTP request. Decode
// chunked bodies before forwarding: tangd receives unambiguous Content-Length
// framing and EOF on stdin, without depending on TCP packet boundaries.
func readNativeRequest(input io.Reader) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(input, nativeMaxWireSize))
	var header []byte
	for {
		line, err := reader.ReadSlice('\n')
		if len(header)+len(line) > nativeMaxHeaderSize {
			return nil, errNativeHeaderTooLarge
		}
		header = append(header, line...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(header) >= 4 && bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			break
		}
	}

	request, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader)))
	if err != nil {
		return nil, err
	}
	// ReadRequest is also used by non-server callers and accepts some header
	// names that a net/http server rejects. Do not silently drop them when Write
	// normalizes the request for tangd.
	for name, values := range request.Header {
		if !validNativeHeaderName(name) {
			return nil, errors.New("invalid request header name")
		}
		for _, value := range values {
			for i := range len(value) {
				if (value[i] < ' ' && value[i] != '\t') || value[i] == 0x7f {
					return nil, errors.New("invalid request header value")
				}
			}
		}
	}
	// On rejection do not Close the parsed body: Close may drain attacker input.
	if request.ContentLength > nativeMaxBodySize {
		return nil, errNativeBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, nativeMaxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > nativeMaxBodySize {
		return nil, errNativeBodyTooLarge
	}
	if err := request.Body.Close(); err != nil {
		return nil, err
	}

	request.Body = http.NoBody
	if len(body) != 0 {
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	request.ContentLength = int64(len(body))
	request.TransferEncoding = nil
	request.Trailer = nil
	request.Header.Del("Trailer")
	request.Close = true
	var out bytes.Buffer
	if err := request.Write(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func validNativeHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}
