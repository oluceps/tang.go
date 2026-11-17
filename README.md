# Tang.go

Tang.go is a pure Go library implementing the server side of ECMR key exchange,
functionally similar to the [Tang project](https://github.com/latchset/tang).
It also provides direct key recovery and a `tangctl` command.

## HTTP server

```go
package main

import (
	"log"

	"github.com/anatol/tang.go"
)

func main() {
	keys, err := tang.ReadKeys("/var/db/tang")
	if err != nil {
		log.Fatal(err)
	}
	srv := tang.NewServer()
	srv.Keys = keys
	srv.Addr = ":8080"
	log.Fatal(srv.ListenAndServe())
}
```

`NewServer` sets a 5-second header-read timeout, 30-second request-read and
response-write timeouts, a 60-second idle timeout, and a 16 KiB header limit.
The recovery body limit is 64 KiB. Configure the embedded `http.Server` before
serving to adjust these values. Routes use the decoded URL path; query parameters
do not form part of key thumbprints.

Initialize a `KeySet` before serving it. Concurrent reads are supported after
initialization; mutation, advertisement recomputation, and changes to retained
JWK objects or `DefaultAdvertisement` must not overlap with requests. To rotate a
running service's keys, build a separate keyset and coordinate its installation
with the embedding application.

Dot-prefixed `.jwk` files are retained but not advertised. This supports recovery
with old keys; hiding a key does not revoke it. Removing recovery authority
requires removing the key from the active keyset.

## Direct recovery

This example uses the current JWX v3 API and dummy, freshly generated keys:

```go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/anatol/tang.go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func main() {
	if err := recoverPoint(); err != nil {
		log.Fatal(err)
	}
}

func recoverPoint() error {
	serverKey, err := tang.GenerateExchangeKey()
	if err != nil {
		return err
	}
	keys := tang.NewKeySet()
	if err := keys.AppendKey(serverKey, true); err != nil {
		return err
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}
	requestKey, err := jwk.Import(&clientKey.PublicKey)
	if err != nil {
		return err
	}
	if err := requestKey.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		return err
	}
	thumbprint, err := serverKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	result, err := keys.RecoverKey(base64.RawURLEncoding.EncodeToString(thumbprint), requestKey)
	if err != nil {
		return err
	}
	var point ecdsa.PublicKey
	if err := jwk.Export(result, &point); err != nil {
		return err
	}
	fmt.Println(point.X, point.Y)
	return nil
}
```

`AppendKey` and `RecomputeAdvertisements` leave the collection and advertisement
caches unchanged on failure. Append does not recompute advertisements. Add a
signing key and call `RecomputeAdvertisements` when advertisements are needed.

## Command line

```sh
go build ./cmd/tangctl
./tangctl create > private.jwk
./tangctl unpack-key --output-dir /var/db/tang private.jwk
./tangctl server --port 8080 --key /var/db/tang
```

Protect redirected private-key output with an appropriate umask, such as `077`.
`unpack-key` creates files with mode `0600` and refuses existing destinations,
including symlinks. It validates and serializes all keys before creating outputs.
A filesystem error during creation can still leave completed files; the error
identifies the failed destination and reports partial completion. It does not
promise an atomic multi-file transaction. Output errors are returned to the caller.

`ReverseTangHandshake` uses a bounded exchange deadline. Embedding applications
can use `ReverseTangHandshakeContext` for cancellation. The reverse protocol
requires complete newline-terminated fields and rejects fields over its limits.

`NativeServer` wraps a locally installed `tangd`. It bounds complete HTTP requests
and connection lifetimes; `Stop` cancels active work and waits for cleanup. The
pure Go HTTP server does not require `tangd`.

## Tests

```sh
go test ./...
go test -race ./...
```

The suite includes pure Go regression tests and native interoperability cases.
Native cases require `clevis` on `PATH` and `tangd` in a supported system location;
cases that require unavailable tools are skipped. The Go dependencies must be
available before running offline tests. Documentation examples are also compiled
as Go examples.

## Acknowledgments

This project has been inspired by [Tang](https://github.com/latchset/tang).
