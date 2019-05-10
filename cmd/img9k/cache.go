package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
)

type diskStatus struct {
	All  uint64 `json:"all"`
	Used uint64 `json:"used"`
	Free uint64 `json:"free"`
}

type cacher struct {
	Handler http.Handler

	sync.Mutex
}

func hashString(name string) string {
	s := sha256.New()
	s.Write([]byte(name))
	return strings.ToUpper(hex.EncodeToString(s.Sum(nil)))
}

func (c *cacher) Available() uint64 {
	return directory.Concat("c").Free()
}

func (c *cacher) serveContent(rw http.ResponseWriter, r *http.Request, name, path string) {
	if strings.Contains(r.Header.Get("Accept-Ranges"), "-") {
		// Cannot serve compressed in this fashion
		http.ServeFile(rw, r, path)
		return
	}

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		file, err := etc.FileController(path, true)
		if err != nil {
			yo.Warn("Cannot open file", path, err)
			return
		}

		tp := http.DetectContentType(file.ReadBytes(512))

		if strings.HasPrefix(tp, "text") && strings.HasSuffix(path, ".svg") {
			tp = "image/svg+xml; charset=utf8"
		}

		yo.Ok("type == ", tp)
		yo.Ok("content == ", path)

		rw.Header().Set("Content-Type", tp)
		rw.Header().Set("Content-Encoding", "gzip")

		file.SeekR(0)
		rw.WriteHeader(200)

		gz := gzip.NewWriter(rw)
		_, err = io.Copy(gz, file)
		if err != nil {
			yo.Warn(err)
		}
		gz.Close()
		file.Close()

		return
	}

	http.ServeFile(rw, r, path)
}

func (c *cacher) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	pth := r.URL.Path[1:]
	yo.Ok("Serving", pth)
	hash := hashString(pth)
	pCachePath := directory.Concat("c").Concat(hash)
	pSrcPath := directory.Concat("i").GetSub(etc.ParseUnixPath(pth))

	if pCachePath.IsExtant() && time.Since(pCachePath.Time()) < Config.CacheDuration.Duration {
		// cached file exists.
		c.serveContent(rw, r, pth, pCachePath.Render())
		return
	}

	// Backend may be down. serve cached file in its place.
	if !pSrcPath.IsExtant() && pCachePath.IsExtant() {
		c.serveContent(rw, r, pth, pCachePath.Render())
		return
	}

	if pSrcPath.IsExtant() == false {
		http.Error(rw, "file not found", 404)
		return
	}

	cacheDir := directory.Concat("c")

	// delete oldest item in cache if we have not enough space.
	for cacheDir.Free() < pSrcPath.Size() || cacheDir.Size() > Config.MaxCacheBytes {
		yo.Ok("erasing until bytes free are more than", cacheDir.Free())

		lru, err := cacheDir.LRU()
		if err != nil {
			yo.Warn(err)
			break
		}

		cacheDir.Concat(lru).Remove()
	}

	pCachePath.Remove()

	f, err := etc.FileController(pCachePath.Render())
	if err != nil {
		yo.Fatal(err)
	}

	if err = f.Flush(); err != nil {
		yo.Fatal(err)
	}

	s, err := etc.FileController(pSrcPath.Render(), true)
	if err != nil {
		yo.Fatal(err)
	}

	if _, err = io.Copy(f, s); err != nil {
		yo.Fatal(err)
	}

	f.Close()
	s.Close()

	c.serveContent(rw, r, pth, pCachePath.Render())
}
