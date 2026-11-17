package tang_test

import (
	"log"

	"github.com/anatol/tang.go"
)

func ExampleNewServer() {
	keys, err := tang.ReadKeys("/var/db/tang")
	if err != nil {
		log.Fatal(err)
	}
	srv := tang.NewServer()
	srv.Keys = keys
	srv.Addr = ":8080"
	log.Fatal(srv.ListenAndServe())
}
