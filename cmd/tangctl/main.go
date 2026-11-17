package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	defaultAlgo = crypto.SHA256
)

func main() {
	var opts struct {
		Create    struct{} `command:"create" description:"Generate a private key"`
		UnpackKey struct {
			OutputDir string `long:"output-dir" default:"." description:"Output directory"`
			Alg       string `long:"alg" description:"Hash algorithm" default:"sha256" choice:"sha1" choice:"sha256"`
			Args      struct {
				Key string `positional-arg-name:"key" required:"true"`
			} `positional-args:"true"`
		} `command:"unpack-key" description:"Unpacks private key into minimal *.jwk files"`
		Public struct {
			Args struct {
				Key []string `positional-arg-name:"key" required:"true"`
			} `positional-args:"true"`
		} `command:"public" description:"Generate a public key (advertisement)"`
		Thumbprint struct {
			Alg  string `long:"alg" description:"Hash algorithm" default:"sha256" choice:"sha1" choice:"sha256"`
			Args struct {
				Key string `positional-arg-name:"key" required:"true"`
			} `positional-args:"true"`
		} `command:"thp" description:"Compute key thumbprint"`
		Server struct {
			Port int      `long:"port" description:"Http port"`
			Key  []string `long:"key" description:"Private key"`
		} `command:"server" description:"Run Tang server"`
		Unlock struct {
			Args struct {
				Address string   `positional-arg-name:"address" required:"true"`
				Key     []string `positional-arg-name:"key" required:"true"`
			} `positional-args:"true"`
		} `command:"unlock" description:"Unlock remote client"`
	}

	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	switch parser.Active.Name {
	case "create":
		err = createKey()
	case "unpack-key":
		err = unpackKey(opts.UnpackKey.OutputDir, opts.UnpackKey.Alg, opts.UnpackKey.Args.Key)
	case "public":
		err = generateAdvertisement(opts.Public.Args.Key)
	case "thp":
		err = generateThumbprint(opts.Thumbprint.Alg, opts.Thumbprint.Args.Key)
	case "server":
		err = startTangServer(opts.Server.Port, opts.Server.Key)
	case "unlock":
		err = unlock(opts.Unlock.Args.Address, opts.Unlock.Args.Key)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func unpackKey(outDir, alg, key string) error {
	data, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	keys, err := jwk.Parse(data)
	if err != nil {
		return err
	}

	var h crypto.Hash
	if alg == "" {
		h = defaultAlgo
	} else {
		h, err = byHashName(alg)
		if err != nil {
			return err
		}
	}

	return unpackKeySet(outDir, h, keys)
}

func unpackKeySet(outDir string, h crypto.Hash, keys jwk.Set) error {
	type output struct {
		name string
		data []byte
	}

	// Serialize and compute every destination before creating any output, so a
	// malformed later key cannot leave an earlier key on disk.
	outputs := make([]output, 0, keys.Len())
	for i := range keys.Len() {
		k, ok := keys.Key(i)
		if !ok {
			return fmt.Errorf("failed to get key at index %d", i)
		}

		keyData, err := json.Marshal(k)
		if err != nil {
			return fmt.Errorf("serialize key at index %d: %w", i, err)
		}

		thp, err := k.Thumbprint(h)
		if err != nil {
			return fmt.Errorf("thumbprint key at index %d: %w", i, err)
		}
		name := base64.RawURLEncoding.EncodeToString(thp)
		outputs = append(outputs, output{path.Join(outDir, name+".jwk"), keyData})
	}

	// Creation is exclusive: existing files (regardless of permissions) and
	// symlinks are rejected. The batch is not atomic: completed files remain
	// on a later failure, and a write/close failure may leave a partial file.
	// Never remove or replace paths on failure; another process may have
	// replaced them.
	completed := make([]string, 0, len(outputs))
	for _, out := range outputs {
		f, err := os.OpenFile(out.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %q: %w; completed files: %q", out.name, err, completed)
		}
		n, writeErr := f.Write(out.data)
		if writeErr == nil && n != len(out.data) {
			writeErr = io.ErrShortWrite
		}
		closeErr := f.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return fmt.Errorf("write/close %q (file may be incomplete): %w; completed files: %q", out.name, err, completed)
		}
		completed = append(completed, out.name)
	}

	return nil
}

func unlock(address string, key []string) error {
	ks, err := tang.ReadKeys(key...)
	if err != nil {
		return err
	}

	return tang.ReverseTangHandshake(address, ks)
}

func startTangServer(port int, key []string) error {
	var err error

	srv := tang.NewServer()
	srv.Keys, err = tang.ReadKeys(key...)
	if err != nil {
		return err
	}
	srv.Addr = ":" + strconv.Itoa(port)
	return srv.ListenAndServe()
}

func byHashName(name string) (crypto.Hash, error) {
	switch name {
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("unknown hash algorithm: %s", name)
	}
}

func generateThumbprint(alg string, key string) error {
	return generateThumbprintTo(os.Stdout, alg, key)
}

func generateThumbprintTo(w io.Writer, alg string, key string) error {
	data, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	keys, err := jwk.Parse(data)
	if err != nil {
		return err
	}

	var h crypto.Hash
	if alg == "" {
		h = defaultAlgo
	} else {
		h, err = byHashName(alg)
		if err != nil {
			return err
		}
	}

	for i := range keys.Len() {
		key, ok := keys.Key(i)
		if !ok {
			return fmt.Errorf("failed to get key at index %d", i)
		}

		thp, err := key.Thumbprint(h)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, base64.RawURLEncoding.EncodeToString(thp)); err != nil {
			return err
		}
	}

	return nil
}

func generateAdvertisement(keys []string) error {
	return generateAdvertisementTo(os.Stdout, keys)
}

func generateAdvertisementTo(w io.Writer, keys []string) error {
	ks, err := tang.ReadKeys(keys...)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, string(ks.DefaultAdvertisement))
	return err
}

func createKey() error {
	return createKeyTo(os.Stdout)
}

func createKeyTo(w io.Writer) error {
	vk, err := tang.GenerateVerifyKey()
	if err != nil {
		return err
	}
	ek, err := tang.GenerateExchangeKey()
	if err != nil {
		return err
	}

	ks := jwk.NewSet()
	ks.AddKey(vk)
	ks.AddKey(ek)

	data, err := json.Marshal(ks)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}
