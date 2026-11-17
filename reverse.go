package tang

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	reverseHandshakeTimeout = 30 * time.Second
	reverseMaxThumbprint    = 128
	reverseMaxExchangeLine  = 64 * 1024
)

var errReverseLineTooLong = errors.New("reverse handshake line too long")

// ReverseTangHandshake performs a key exchange with a remote clevis client.
// The complete handshake is limited to 30 seconds.
func ReverseTangHandshake(address string, ks *KeySet) error {
	return ReverseTangHandshakeContext(context.Background(), address, ks)
}

// ReverseTangHandshakeContext performs a reverse key exchange, bounded by the
// earlier of the context deadline and 30 seconds. Cancellation closes the socket.
func ReverseTangHandshakeContext(ctx context.Context, address string, ks *KeySet) error {
	ctx, cancel := context.WithTimeout(ctx, reverseHandshakeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return reverseTangHandshakeConn(ctx, conn, ks)
}

// reverseTangHandshakeConn owns conn and always closes it before returning.
func reverseTangHandshakeConn(ctx context.Context, conn net.Conn, ks *KeySet) (err error) {
	ctx, cancel := context.WithTimeout(ctx, reverseHandshakeTimeout)
	defer cancel()
	defer conn.Close()
	// AfterFunc wakes a blocked read or write even when cancellation has no
	// deadline. Join the callback so it cannot outlive the handshake.
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if ks == nil {
		return errors.New("nil key set")
	}

	if err := writeReverseLine(conn, ks.DefaultAdvertisement); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	thumbprint, err := readReverseLine(reader, reverseMaxThumbprint)
	if err != nil {
		return fmt.Errorf("read thumbprint: %w", err)
	}
	exchangeKey, err := readReverseLine(reader, reverseMaxExchangeLine)
	if err != nil {
		return fmt.Errorf("read exchange key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	out, err := ks.Recover(string(thumbprint), exchangeKey)
	if err != nil {
		return err
	}
	return writeReverseLine(conn, out)
}

// readReverseLine accepts LF or CRLF, limits the payload length, and requires a
// terminator. Unlike ReadLine it never accepts a partial buffer as a whole line.
func readReverseLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if b == '\n' {
			return bytes.TrimSuffix(line, []byte("\r")), nil
		}
		// Only a CR immediately followed by LF may exceed the payload limit.
		if len(line) > limit || (len(line) == limit && b != '\r') {
			return nil, errReverseLineTooLong
		}
		line = append(line, b)
	}
}

func writeReverseLine(output io.Writer, line []byte) error {
	// Copy handles short writes and reports io.ErrShortWrite instead of silently
	// truncating a protocol message. Neither advertisements nor keys are logged.
	if _, err := io.Copy(output, bytes.NewReader(line)); err != nil {
		return err
	}
	_, err := io.Copy(output, bytes.NewReader([]byte("\n")))
	return err
}
