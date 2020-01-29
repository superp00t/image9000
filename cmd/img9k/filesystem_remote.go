package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/superp00t/image9000/i9k"
)

type remote struct {
	Certificate       tls.Certificate
	serverFingerprint string
	*i9k.FileStorageClient
}

func (r *remote) Stat(path string) (os.FileInfo, error) {
	sr, err := r.FileStorageClient.Stat(context.Background(), &i9k.StatRequest{
		Path: path,
	})
	if err != nil {
		return nil, err
	}

	return sr, nil
}

func (r *remote) ReadBytesAt(path string, offset, size int64) ([]byte, error) {
	rc, err := r.FileStorageClient.ReadAt(context.Background(), &i9k.ReadAtRequest{
		Path:        path,
		StartOffset: uint64(offset),
		Size:        uint64(size),
	})
	if err != nil {
		return nil, err
	}
	return rc.Data, nil
}

func (r *remote) CopyFileTo(path string, wr io.Writer) error {
	st, err := r.Stat(path)
	if err != nil {
		return err
	}

	size := st.Size()

	for x := int64(0); x < size; {
		lo := x
		hi := lo + i9k.MaxChunkSize
		if hi > size {
			hi = size
		}

		data, err := r.ReadBytesAt(path, lo, hi-lo)
		if err != nil {
			return err
		}

		_, err = wr.Write(data)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *remote) dialContext(ctx context.Context, address string) (net.Conn, error) {
	cn, err := tls.Dial("tcp", address, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{r.Certificate},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	certs := cn.ConnectionState().PeerCertificates

	if len(certs) != 1 {
		return nil, fmt.Errorf("peer certificate wrong size")
	}

	fp, err := i9k.GetCertFingerprint(certs[0])
	if err != nil {
		panic(err)
	}

	if fp != r.serverFingerprint {
		return nil, fmt.Errorf("server has invalid fingerprint %s", fp)
	}

	return cn, nil
}

func (r *remote) List() ([]*i9k.DirectoryEnt, error) {
	dl, err := r.ListDirectory(context.Background(), &i9k.Empty{})
	if err != nil {
		return nil, err
	}

	return dl.Results, nil
}
