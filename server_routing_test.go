package tang

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestAdvertisementRoutesIgnoreQuery(t *testing.T) {
	t.Parallel()
	srv := NewServer()
	srv.Keys = NewKeySet()
	srv.Keys.DefaultAdvertisement = []byte("default advertisement")
	srv.Keys.byThumbprint["fixture"] = &tangKey{advertisement: []byte("key advertisement")}

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/adv?cache=1", "default advertisement"},
		{"/adv/?cache=1", "default advertisement"},
		{"/adv/fixture?cache=1", "key advertisement"},
		{"/%61dv/fixture?cache=1", "key advertisement"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if response.Code != http.StatusOK || response.Body.String() != tc.want {
				t.Fatalf("response = %d %q, want 200 %q", response.Code, response.Body.String(), tc.want)
			}
		})
	}
}

func TestRecoveryRouteIgnoresQuery(t *testing.T) {
	t.Parallel()
	key, err := GenerateExchangeKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := NewKeySet()
	if err := ks.AppendKey(key, true); err != nil {
		t.Fatal(err)
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := jwk.Import(&client.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := requestKey.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(requestKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer()
	srv.Keys = ks
	response := httptest.NewRecorder()
	path := "/rec/" + base64.RawURLEncoding.EncodeToString(thumbprint) + "?cache=1"
	srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if _, err := jwk.ParseKey(response.Body.Bytes()); err != nil {
		t.Fatalf("invalid recovery response: %v", err)
	}
}

func TestIncompleteRecoveryBodyTimesOut(t *testing.T) {
	t.Parallel()
	srv := NewServer()
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatal("server must have nonzero default deadlines")
	}
	srv.ReadTimeout = 50 * time.Millisecond
	srv.Keys = NewKeySet()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve(listener)

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /rec/nonexistent HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("server did not finish the incomplete request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusInternalServerError)
	}
}
