package tang

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

type failingThumbprintKey struct {
	jwk.Key
	failHash crypto.Hash
	err      error
}

func (k *failingThumbprintKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if hash == k.failHash {
		return nil, k.err
	}
	return k.Key.Thumbprint(hash)
}

func TestAppendKeyFailureIsAtomic(t *testing.T) {
	t.Parallel()

	existing, err := GenerateVerifyKey()
	require.NoError(t, err)
	other, err := GenerateVerifyKey()
	require.NoError(t, err)
	thumbprintErr := errors.New("thumbprint failed")

	for _, tc := range []struct {
		name string
		key  jwk.Key
	}{
		{name: "nil"},
		{
			name: "new thumbprints",
			key:  &failingThumbprintKey{Key: other, failHash: crypto.SHA256, err: thumbprintErr},
		},
		{
			name: "existing thumbprints",
			key:  &failingThumbprintKey{Key: existing, failHash: crypto.SHA256, err: thumbprintErr},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ks := NewKeySet()
			require.NoError(t, ks.AppendKey(existing, true))
			original := ks.keys[0]

			err := ks.AppendKey(tc.key, false)
			if tc.key == nil {
				require.ErrorContains(t, err, "nil key")
			} else {
				require.ErrorIs(t, err, thumbprintErr)
			}
			require.Len(t, ks.keys, 1)
			require.Same(t, original, ks.keys[0])
			require.Len(t, ks.byThumbprint, len(algos))
			for _, hash := range algos {
				thumbprint, err := existing.Thumbprint(hash)
				require.NoError(t, err)
				require.Same(t, original, ks.byThumbprint[base64.RawURLEncoding.EncodeToString(thumbprint)])
			}
		})
	}
}

func TestRecomputeAdvertisementsRetainedSignerFailureIsAtomic(t *testing.T) {
	t.Parallel()

	ks := NewKeySet()
	for i := 0; i < 3; i++ {
		key, err := GenerateVerifyKey()
		require.NoError(t, err)
		require.NoError(t, ks.AppendKey(key, i == 0))
	}
	require.NoError(t, ks.RecomputeAdvertisements())
	oldDefault := append([]byte(nil), ks.DefaultAdvertisement...)
	oldAdvertisements := make([][]byte, len(ks.keys))
	for i, key := range ks.keys {
		require.NotEmpty(t, key.advertisement)
		oldAdvertisements[i] = append([]byte(nil), key.advertisement...)
	}

	// Change the payload so an early publication cannot match the old caches.
	exchange, err := GenerateExchangeKey()
	require.NoError(t, err)
	require.NoError(t, ks.AppendKey(exchange, true))
	// The last retained signer fails after the earlier advertisements are computed.
	require.NoError(t, ks.keys[2].Remove(jwk.AlgorithmKey))
	require.ErrorContains(t, ks.RecomputeAdvertisements(), "does not have an algorithm")

	require.Equal(t, oldDefault, ks.DefaultAdvertisement)
	for i, advertisement := range oldAdvertisements {
		require.Equal(t, advertisement, ks.keys[i].advertisement)
	}
	require.Nil(t, ks.keys[3].advertisement)
}

func TestRecomputeAdvertisementsClearsIneligibleCaches(t *testing.T) {
	t.Parallel()

	ks := NewKeySet()
	for i := 0; i < 3; i++ {
		key, err := GenerateVerifyKey()
		require.NoError(t, err)
		require.NoError(t, ks.AppendKey(key, i != 2))
	}
	require.NoError(t, ks.RecomputeAdvertisements())
	for _, key := range ks.keys {
		require.NotEmpty(t, key.advertisement)
	}

	// Both advertised and retained keys can lose their signing eligibility.
	for _, key := range ks.keys[1:] {
		require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{}))
	}
	require.NoError(t, ks.RecomputeAdvertisements())
	require.NotEmpty(t, ks.DefaultAdvertisement)
	require.Equal(t, ks.DefaultAdvertisement, ks.keys[0].advertisement)
	require.Nil(t, ks.keys[1].advertisement)
	require.Nil(t, ks.keys[2].advertisement)
}

func TestSignOnlyAdvertiser(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"alone", "with another signer"} {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateVerifyKey()
			require.NoError(t, err)
			require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpSign}))
			ks := NewKeySet()
			require.NoError(t, ks.AppendKey(key, true))
			set := jwk.NewSet()
			require.NoError(t, set.AddKey(key))
			if name == "with another signer" {
				other, err := GenerateVerifyKey()
				require.NoError(t, err)
				require.NoError(t, ks.AppendKey(other, true))
				require.NoError(t, set.AddKey(other))
			}
			require.NoError(t, ks.RecomputeAdvertisements())
			require.Equal(t, ks.DefaultAdvertisement, ks.keys[0].advertisement)

			var private ecdsa.PrivateKey
			require.NoError(t, jwk.Export(key, &private))
			payload, err := jws.Verify(ks.DefaultAdvertisement, jws.WithKey(jwa.ES512(), &private.PublicKey))
			require.NoError(t, err)
			message, err := jws.Parse(ks.DefaultAdvertisement)
			require.NoError(t, err)
			require.Len(t, message.Signatures(), set.Len())

			// Public projection preserves the key's metadata and omits private material.
			public, err := jwk.PublicSetOf(set)
			require.NoError(t, err)
			expected, err := json.Marshal(public)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), string(payload))
		})
	}
}

func TestRetainedSignerAdvertisement(t *testing.T) {
	t.Parallel()

	current, err := GenerateVerifyKey()
	require.NoError(t, err)
	retained, err := GenerateVerifyKey()
	require.NoError(t, err)
	exchange, err := GenerateExchangeKey()
	require.NoError(t, err)
	ks := NewKeySet()
	require.NoError(t, ks.AppendKey(current, true))
	require.NoError(t, ks.AppendKey(exchange, true))
	require.NoError(t, ks.AppendKey(retained, false))
	require.NoError(t, ks.RecomputeAdvertisements())

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(current))
	require.NoError(t, set.AddKey(exchange))
	public, err := jwk.PublicSetOf(set)
	require.NoError(t, err)
	expected, err := json.Marshal(public)
	require.NoError(t, err)
	var currentPrivate ecdsa.PrivateKey
	require.NoError(t, jwk.Export(current, &currentPrivate))
	payload, err := jws.Verify(ks.DefaultAdvertisement, jws.WithKey(jwa.ES512(), &currentPrivate.PublicKey))
	require.NoError(t, err)
	require.JSONEq(t, string(expected), string(payload))
	message, err := jws.Parse(ks.DefaultAdvertisement)
	require.NoError(t, err)
	require.Len(t, message.Signatures(), 1)

	advertisement := ks.keys[2].advertisement
	message, err = jws.Parse(advertisement)
	require.NoError(t, err)
	require.Len(t, message.Signatures(), 2)
	for _, key := range []jwk.Key{current, retained} {
		var private ecdsa.PrivateKey
		require.NoError(t, jwk.Export(key, &private))
		payload, err := jws.Verify(advertisement, jws.WithKey(jwa.ES512(), &private.PublicKey))
		require.NoError(t, err)
		require.JSONEq(t, string(expected), string(payload))
	}
}

func TestSignPayloadRejectsNonSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	key, err := GenerateVerifyKey()
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.A256GCM()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))

	advertisement, err := signPayload([]byte("payload"), set)
	require.ErrorContains(t, err, "not a signature algorithm")
	require.Nil(t, advertisement)
}

func TestRecoverRequestKeyOps(t *testing.T) {
	t.Parallel()

	server, err := GenerateExchangeKey()
	require.NoError(t, err)
	ks := NewKeySet()
	require.NoError(t, ks.AppendKey(server, true))
	thumbprint, err := server.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thp := base64.RawURLEncoding.EncodeToString(thumbprint)
	ephemeral, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		ops     []jwk.KeyOperation
		allowed bool
	}{
		{name: "absent", allowed: true},
		{name: "explicit empty", ops: []jwk.KeyOperation{}},
		{name: "derive", ops: []jwk.KeyOperation{jwk.KeyOpDeriveKey}, allowed: true},
		{name: "sign only", ops: []jwk.KeyOperation{jwk.KeyOpSign}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := jwk.Import(&ephemeral.PublicKey)
			require.NoError(t, err)
			require.NoError(t, request.Set(jwk.AlgorithmKey, "ECMR"))
			if tc.ops != nil {
				require.NoError(t, request.Set(jwk.KeyOpsKey, tc.ops))
			}
			_, present := request.KeyOps()
			require.Equal(t, tc.ops != nil, present)
			require.Equal(t, tc.allowed, keyValidForUse(request, []jwk.KeyOperation{jwk.KeyOpDeriveKey}))

			recovered, err := ks.RecoverKey(thp, request)
			if tc.allowed {
				require.NoError(t, err)
				require.NotNil(t, recovered)
			} else {
				require.ErrorContains(t, err, "expecting derive key in the request")
				require.Nil(t, recovered)
			}
		})
	}
}
