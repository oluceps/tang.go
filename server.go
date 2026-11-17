package tang

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// Server is an HTTP server that handles Tang exchange requests.
// Set Keys before serving, and do not mutate that KeySet while requests are active.
type Server struct {
	http.Server
	Keys *KeySet
}

func (srv *Server) advertiseKey(w http.ResponseWriter, req *http.Request) {
	uri := req.URL.Path

	var thumbprint string
	if strings.HasPrefix(uri, "/adv/") {
		thumbprint = uri[5:]
	}

	if thumbprint != "" {
		key, found := srv.Keys.byThumbprint[thumbprint]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if key.advertisement == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		_, _ = w.Write(key.advertisement)
	} else {
		_, _ = w.Write(srv.Keys.DefaultAdvertisement)
	}
}

func (srv *Server) recoverKey(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	const maxBodySize = 64 * 1024 // 64KB

	in, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(in) > maxBodySize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	thp := strings.TrimPrefix(req.URL.Path, "/rec/")
	out, err := srv.Keys.Recover(thp, in)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/jwk+json")
	_, _ = w.Write(out)
}

func (srv *Server) handleRequest(w http.ResponseWriter, req *http.Request) {
	uri := req.URL.Path
	if uri == "/adv" || strings.HasPrefix(uri, "/adv/") {
		srv.advertiseKey(w, req)
	} else if strings.HasPrefix(uri, "/rec/") {
		srv.recoverKey(w, req)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// NewServer creates an HTTP server with bounded header, body, and idle reads.
// Callers may configure the embedded http.Server before serving.
func NewServer() *Server {
	srv := Server{Server: http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}}
	srv.Handler = http.HandlerFunc(srv.handleRequest)
	return &srv
}
