package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
)

type diskStatus struct {
	All  uint64 `json:"all"`
	Used uint64 `json:"used"`
	Free uint64 `json:"free"`
}

type cacher struct {
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

func extractContentType(rw http.ResponseWriter, path string) {
	ext := filepath.Ext(path)
	if ext != "" {
		ex := ext[1:]
		for mime, extension := range Config.AcceptedFmt {
			if extension == ex {
				rw.Header().Set("Content-Type", mime)
			}
		}
	}
}

func (c *cacher) serveFile(rw http.ResponseWriter, r *http.Request, path string) {
	finf, err := fsystem.Stat(path)
	if err != nil {
		yo.Warn(err)
		http.Error(rw, "could not stat file "+path, http.StatusInternalServerError)
		return
	}

	fsrs := &filesystemReadSeeker{
		Path:   path,
		Offset: 0,
		Size:   finf.Size(),
	}

	extractContentType(rw, path)
	http.ServeContent(rw, r, path, finf.ModTime(), fsrs)
}

func (c *cacher) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	pth := r.URL.Path[1:]
	yo.Ok("Serving", pth)
	hash := hashString(pth)
	pCachePath := directory.Concat("c").Concat(hash)

	if pCachePath.IsExtant() && time.Since(pCachePath.Time()) < Config.CacheDuration.Duration {
		// cached file exists.
		extractContentType(rw, pth)
		http.ServeFile(rw, r, pCachePath.Render())
		return
	}

	realFile, err := fsystem.Stat(pth)
	if err != nil {
		// serve cached file in case of backend outage.
		if pCachePath.IsExtant() {
			extractContentType(rw, pth)
			http.ServeFile(rw, r, pCachePath.Render())
			return
		}

		http.Error(rw, "not found", http.StatusNotFound)
		return
	}

	// do not cache large files.
	if realFile.Size() > 250*etc.MB {
		c.serveFile(rw, r, pth)
		return
	}

	cacheDir := directory.Concat("c")

	// delete oldest item in cache if we have not enough space.
	for int64(cacheDir.Free()) < realFile.Size() || cacheDir.Size() > Config.MaxCacheBytes {
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

	s := &filesystemReadSeeker{
		Path:   pth,
		Offset: 0,
		Size:   realFile.Size(),
	}

	i, err := io.Copy(f, s)
	if err != nil {
		yo.Fatal(err)
	}

	fmt.Println("Created cache", i, "bytes", spew.Sdump(s))

	f.Close()

	extractContentType(rw, pth)
	http.ServeFile(rw, r, pCachePath.Render())
}
