package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func testKeyFile(t *testing.T) (string, jwk.Set) {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, createKeyTo(&out))
	keys, err := jwk.Parse(out.Bytes())
	require.NoError(t, err)
	require.Equal(t, 2, keys.Len())
	name := filepath.Join(t.TempDir(), "input.jwk")
	require.NoError(t, os.WriteFile(name, out.Bytes(), 0o600))
	return name, keys
}

func testKeyOutput(t *testing.T, outDir string, keys jwk.Set, i int, h crypto.Hash) (string, []byte) {
	t.Helper()
	key, ok := keys.Key(i)
	require.True(t, ok)
	thp, err := key.Thumbprint(h)
	require.NoError(t, err)
	data, err := json.Marshal(key)
	require.NoError(t, err)
	return filepath.Join(outDir, base64.RawURLEncoding.EncodeToString(thp)+".jwk"), data
}

func TestUnpackKeyPrivateOutputs(t *testing.T) {
	input, keys := testKeyFile(t)
	for _, alg := range []string{"", "sha256", "sha1"} {
		t.Run("algorithm="+alg, func(t *testing.T) {
			outDir := t.TempDir()
			require.NoError(t, unpackKey(outDir, alg, input))
			h := defaultAlgo
			if alg != "" {
				var err error
				h, err = byHashName(alg)
				require.NoError(t, err)
			}
			for i := range keys.Len() {
				name, want := testKeyOutput(t, outDir, keys, i, h)
				got, err := os.ReadFile(name)
				require.NoError(t, err)
				require.Equal(t, want, got)
				info, err := os.Stat(name)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			}
			entries, err := os.ReadDir(outDir)
			require.NoError(t, err)
			require.Len(t, entries, keys.Len())
		})
	}
}

func TestUnpackKeyRejectsExistingFiles(t *testing.T) {
	input, keys := testKeyFile(t)
	for _, mode := range []os.FileMode{0o600, 0o644, 0o666} {
		t.Run(fmt.Sprintf("mode=%o", mode), func(t *testing.T) {
			outDir := t.TempDir()
			name, _ := testKeyOutput(t, outDir, keys, 0, defaultAlgo)
			original := []byte("existing content must survive")
			require.NoError(t, os.WriteFile(name, original, mode))
			// Set exact existing permissions independently of the process umask.
			require.NoError(t, os.Chmod(name, mode))

			err := unpackKey(outDir, "", input)
			require.ErrorIs(t, err, os.ErrExist)
			require.ErrorContains(t, err, name)
			require.ErrorContains(t, err, "completed files: []")
			got, err := os.ReadFile(name)
			require.NoError(t, err)
			require.Equal(t, original, got)
			info, err := os.Stat(name)
			require.NoError(t, err)
			require.Equal(t, mode, info.Mode().Perm())
			entries, err := os.ReadDir(outDir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestUnpackKeyRejectsSymlinks(t *testing.T) {
	input, keys := testKeyFile(t)
	for _, dangling := range []bool{false, true} {
		t.Run(fmt.Sprintf("dangling=%t", dangling), func(t *testing.T) {
			outDir := t.TempDir()
			name, _ := testKeyOutput(t, outDir, keys, 0, defaultAlgo)
			target := filepath.Join(t.TempDir(), "target")
			original := []byte("symlink target must survive")
			if !dangling {
				require.NoError(t, os.WriteFile(target, original, 0o644))
				require.NoError(t, os.Chmod(target, 0o644))
			}
			require.NoError(t, os.Symlink(target, name))

			err := unpackKey(outDir, "", input)
			require.ErrorIs(t, err, os.ErrExist)
			require.ErrorContains(t, err, name)
			link, err := os.Readlink(name)
			require.NoError(t, err)
			require.Equal(t, target, link)
			if dangling {
				_, err := os.Lstat(target)
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				got, err := os.ReadFile(target)
				require.NoError(t, err)
				require.Equal(t, original, got)
				info, err := os.Stat(target)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
			}
			entries, err := os.ReadDir(outDir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestUnpackKeyPartialCompletion(t *testing.T) {
	input, keys := testKeyFile(t)
	outDir := t.TempDir()
	first, want := testKeyOutput(t, outDir, keys, 0, defaultAlgo)
	second, _ := testKeyOutput(t, outDir, keys, 1, defaultAlgo)
	original := []byte("existing second destination")
	require.NoError(t, os.WriteFile(second, original, 0o644))
	require.NoError(t, os.Chmod(second, 0o644))

	err := unpackKey(outDir, "", input)
	require.ErrorIs(t, err, os.ErrExist)
	require.ErrorContains(t, err, fmt.Sprintf("create %q", second))
	require.ErrorContains(t, err, fmt.Sprintf("completed files: %q", []string{first}))
	got, err := os.ReadFile(first)
	require.NoError(t, err)
	require.Equal(t, want, got)
	info, err := os.Stat(first)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	got, err = os.ReadFile(second)
	require.NoError(t, err)
	require.Equal(t, original, got)
	info, err = os.Stat(second)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

// These wrappers simulate a later key that parsed but fails during preflight.
// Embedding preserves the rest of the JWK interfaces without reimplementing them.
type failingKeySet struct {
	jwk.Set
	last jwk.Key
}

func (s failingKeySet) Key(i int) (jwk.Key, bool) {
	if i == s.Len()-1 {
		return s.last, true
	}
	return s.Set.Key(i)
}

type failingKey struct {
	jwk.Key
	marshalErr    error
	thumbprintErr error
}

func (k failingKey) MarshalJSON() ([]byte, error) {
	if k.marshalErr != nil {
		return nil, k.marshalErr
	}
	return json.Marshal(k.Key)
}

func (k failingKey) Thumbprint(h crypto.Hash) ([]byte, error) {
	if k.thumbprintErr != nil {
		return nil, k.thumbprintErr
	}
	return k.Key.Thumbprint(h)
}

func TestUnpackKeyPreflightsAllKeys(t *testing.T) {
	_, keys := testKeyFile(t)
	last, ok := keys.Key(keys.Len() - 1)
	require.True(t, ok)
	failure := errors.New("malformed later key")
	for _, tc := range []struct {
		name string
		key  failingKey
	}{
		{"serialize", failingKey{Key: last, marshalErr: failure}},
		{"thumbprint", failingKey{Key: last, thumbprintErr: failure}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()
			err := unpackKeySet(outDir, defaultAlgo, failingKeySet{Set: keys, last: tc.key})
			require.ErrorIs(t, err, failure)
			require.ErrorContains(t, err, tc.name+" key at index 1")
			entries, err := os.ReadDir(outDir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestUnpackKeyMalformedLaterInput(t *testing.T) {
	_, keys := testKeyFile(t)
	_, first := testKeyOutput(t, "", keys, 0, defaultAlgo)
	input := filepath.Join(t.TempDir(), "malformed.jwk")
	data := append([]byte(`{"keys":[`), first...)
	data = append(data, []byte(`,{"kty":"invalid"}]}`)...)
	require.NoError(t, os.WriteFile(input, data, 0o600))
	outDir := t.TempDir()
	require.Error(t, unpackKey(outDir, "", input))
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

type failingWriter struct {
	err       error
	successes int
	calls     int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls <= w.successes {
		return len(p), nil
	}
	return 0, w.err
}

func TestPrintingPropagatesWriteErrors(t *testing.T) {
	input, _ := testKeyFile(t)
	failure := errors.New("output failed")
	for _, tc := range []struct {
		name string
		run  func(io.Writer) error
	}{
		{"create", createKeyTo},
		{"public", func(w io.Writer) error { return generateAdvertisementTo(w, []string{input}) }},
		{"thumbprint", func(w io.Writer) error { return generateThumbprintTo(w, "", input) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &failingWriter{err: failure}
			require.ErrorIs(t, tc.run(w), failure)
			require.Equal(t, 1, w.calls)
		})
	}

	t.Run("later thumbprint", func(t *testing.T) {
		w := &failingWriter{err: failure, successes: 1}
		require.ErrorIs(t, generateThumbprintTo(w, "", input), failure)
		require.Equal(t, 2, w.calls)
	})
}

func TestPrintingOutput(t *testing.T) {
	input, keys := testKeyFile(t)
	var out bytes.Buffer
	require.NoError(t, generateThumbprintTo(&out, "", input))
	var want strings.Builder
	for i := range keys.Len() {
		key, ok := keys.Key(i)
		require.True(t, ok)
		thp, err := key.Thumbprint(defaultAlgo)
		require.NoError(t, err)
		fmt.Fprintln(&want, base64.RawURLEncoding.EncodeToString(thp))
	}
	require.Equal(t, want.String(), out.String())

	out.Reset()
	require.NoError(t, generateAdvertisementTo(&out, []string{input}))
	require.True(t, json.Valid(out.Bytes()))
	require.True(t, strings.HasSuffix(out.String(), "\n"))
}
