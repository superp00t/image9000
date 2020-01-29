package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
	"github.com/superp00t/image9000/i9k"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type storageServerConfig struct {
	RemoteFingerprint string `json:"remote_fingerprint"`
	Listen            string `json:"listen"`
	Directory         string `json:"directory"`
}

func runStorage(s []string) {
	configDir := etc.ParseSystemPath(s[0])
	if configDir.IsExtant() == false {
		if err := configDir.MakeDir(); err != nil {
			panic(err)
		}
	}

	if configDir.Exists("config.json") == false {
		fmt.Println("no config file")
		os.Exit(1)
	}

	var config storageServerConfig

	b, err := configDir.Concat("config.json").ReadAll()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(b, &config)
	if err != nil {
		panic(err)
	}

	if configDir.Exists("cert.pem") == false {
		if err := i9k.GenerateTLSKeyPair(configDir.Render()); err != nil {
			panic(err)
		}
	}

	fp, _ := i9k.GetCertFileFingerprint(configDir.Concat("cert.pem").Render())
	yo.Ok("Storage server fingerprint: ", fp)

	creds, err := tls.LoadX509KeyPair(configDir.Concat("cert.pem").Render(), configDir.Concat("key.pem").Render())
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	base := etc.Path{}

	if config.Directory == "" {
		base = configDir.Concat("i")
	} else {
		lPath := etc.ParseSystemPath(config.Directory)
		base = configDir.GetSub(lPath)
	}

	if base.IsExtant() == false {
		yo.Ok("Creating", base.Render())
		base.MakeDir()
	}

	yo.Ok("Serving", base.Render())

	conf := &tls.Config{
		Certificates: []tls.Certificate{creds},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAnyClientCert,
	}

	storageServer := new(i9k.FileStorageServer)
	storageServer.Base = base
	storageServer.Fingerprint = config.RemoteFingerprint

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(conf)))
	i9k.RegisterStorageServer(grpcServer, storageServer)

	l, err := net.Listen("tcp", config.Listen)
	if err != nil {
		panic(err)
	}

	grpcServer.Serve(l)
}
