package tang

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestReverseTangHandshake(t *testing.T) {
	// Generate disposable keys instead of depending on on-disk key fixtures.
	ks := NewKeySet()
	key, err := GenerateExchangeKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.AppendKey(key, true); err != nil {
		t.Fatal(err)
	}
	ks.DefaultAdvertisement = []byte(`{"keys":[]}`)
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	thp := base64.RawURLEncoding.EncodeToString(thumbprint)
	peerKey, err := GenerateExchangeKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.PublicKeyOf(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	// A legal extension makes the exchange span the former 4 KiB buffer.
	fields["padding"] = strings.Repeat("x", 9000)
	payload, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ks.Recover(thp, payload)
	if err != nil {
		t.Fatal(err)
	}

	client, peer := net.Pipe()
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- reverseTangHandshakeConn(ctx, client, ks) }()
	reader := bufio.NewReader(peer)
	advertisement, err := readReverseLine(reader, reverseMaxExchangeLine)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(advertisement, ks.DefaultAdvertisement) {
		t.Fatal("unexpected advertisement")
	}
	input := thp + "\r\n" + string(payload) + "\n"
	if _, err := io.Copy(peer, iotest.OneByteReader(strings.NewReader(input))); err != nil {
		t.Fatal(err)
	}
	got, err := readReverseLine(reader, reverseMaxExchangeLine)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("unexpected exchange response")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("handshake did not finish")
	}
}

func TestReverseReadLineLimits(t *testing.T) {
	for _, limit := range []int{reverseMaxThumbprint, reverseMaxExchangeLine} {
		for _, ending := range []string{"\n", "\r\n"} {
			input := strings.Repeat("x", limit) + ending
			line, err := readReverseLine(bufio.NewReader(iotest.OneByteReader(strings.NewReader(input))), limit)
			if err != nil || len(line) != limit {
				t.Fatalf("limit %d: length = %d, error = %v", limit, len(line), err)
			}
		}
		for _, ending := range []string{"", "\n", "\r\n"} {
			input := strings.Repeat("x", limit+1) + ending
			if _, err := readReverseLine(bufio.NewReader(strings.NewReader(input)), limit); !errors.Is(err, errReverseLineTooLong) {
				t.Fatalf("limit %d: oversized line error = %v", limit, err)
			}
		}
	}
	for _, input := range []string{"", "partial", "partial\r"} {
		if _, err := readReverseLine(bufio.NewReader(strings.NewReader(input)), reverseMaxThumbprint); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("unterminated line error = %v", err)
		}
	}
}

func TestReverseRejectInvalidLines(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  error
	}{
		{"long thumbprint", strings.Repeat("x", reverseMaxThumbprint+1), errReverseLineTooLong},
		{"long exchange", "thumbprint\n" + strings.Repeat("x", reverseMaxExchangeLine+1), errReverseLineTooLong},
		{"missing thumbprint terminator", "thumbprint", io.ErrUnexpectedEOF},
		{"missing exchange terminator", "thumbprint\n{}", io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- reverseTangHandshakeConn(ctx, client, NewKeySet()) }()
			if _, err := bufio.NewReader(peer).ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			// Closing after the write supplies EOF for unterminated lines.
			_, _ = io.WriteString(peer, tc.input)
			_ = peer.Close()
			select {
			case err := <-finished:
				if !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
			case <-ctx.Done():
				t.Fatal("invalid input did not terminate handshake")
			}
		})
	}
}

func TestReverseContextCancellation(t *testing.T) {
	for _, stage := range []string{"advertisement write", "thumbprint read", "exchange read", "partial exchange"} {
		t.Run(stage, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// No context deadline: cancellation itself must close the socket.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			ks := NewKeySet()
			ks.DefaultAdvertisement = []byte("advertisement")
			go func() { finished <- reverseTangHandshakeConn(ctx, client, ks) }()
			if stage != "advertisement write" {
				if _, err := bufio.NewReader(peer).ReadString('\n'); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "exchange read" || stage == "partial exchange" {
				if _, err := io.WriteString(peer, "thumbprint\n"); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "partial exchange" {
				if _, err := io.WriteString(peer, "{\"partial\":"); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want context.Canceled", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not unblock handshake")
			}
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("canceled handshake left its socket open")
			}
		})
	}
}

func TestReverseContextDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// An idle peer blocks the initial advertisement write.
	err := reverseTangHandshakeConn(ctx, client, NewKeySet())
	if !errors.Is(err, context.DeadlineExceeded) {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("error = %v, want a deadline error", err)
		}
	}
}

func TestReverseTangHandshakeContextCanceledBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ReverseTangHandshakeContext(ctx, "127.0.0.1:1", NewKeySet()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestReverseWriteLineShortWrite(t *testing.T) {
	if err := writeReverseLine(reverseShortWriter{}, []byte("message")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

type reverseShortWriter struct{}

func (reverseShortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }
