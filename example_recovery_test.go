package tang_test

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

func ExampleKeySet_RecoverKey() {
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
