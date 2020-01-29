package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
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

	http.ServeContent(rw, r, path, finf.ModTime(), fsrs)
}

func (c *cacher) serveContent(rw http.ResponseWriter, r *http.Request, name, path string) {
	// if strings.Contains(r.Header.Get("Accept-Ranges"), "-") {
	// 	// Cannot serve compressed in this fashion
	// 	c.serveFile(rw, r, path)
	// 	return
	// }

	// if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
	// 	file, err := etc.FileController(path, true)
	// 	if err != nil {
	// 		yo.Warn("Cannot open file", path, err)
	// 		return
	// 	}

	// 	tp := http.DetectContentType(file.ReadBytes(512))

	// 	typeMap := map[string]string{
	// 		"svg": "image/svg+xml; charset=utf-8",
	// 		"css": "text/css; charset=utf-8",
	// 		"js":  "application/javascript; charset=utf-8",
	// 	}

	// 	s := strings.Split(name, ".")
	// 	typ := s[len(s)-1]
	// 	if typeMap[typ] != "" {
	// 		tp = typeMap[typ]
	// 	} else {
	// 		yo.Warn(s)
	// 		yo.Warn(typ)
	// 		yo.Warn(tp)
	// 	}

	// 	yo.Ok("type == ", tp)
	// 	yo.Ok("content == ", path)

	// 	rw.Header().Set("Content-Type", tp)
	// 	rw.Header().Set("Content-Encoding", "gzip")

	// 	file.SeekR(0)
	// 	rw.WriteHeader(200)

	// 	gz := gzip.NewWriter(rw)
	// 	_, err = io.Copy(gz, file)
	// 	if err != nil {
	// 		yo.Warn(err)
	// 	}
	// 	gz.Close()
	// 	file.Close()

	// 	return
	// }

	c.serveFile(rw, r, path)
}

func (c *cacher) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	pth := r.URL.Path[1:]
	yo.Ok("Serving", pth)
	hash := hashString(pth)
	pCachePath := directory.Concat("c").Concat(hash)

	if pCachePath.IsExtant() && time.Since(pCachePath.Time()) < Config.CacheDuration.Duration {
		// cached file exists.
		http.ServeFile(rw, r, pCachePath.Render())
		return
	}

	realFile, err := fsystem.Stat(pth)
	if err != nil {
		// serve cached file in case of backend outage.
		if pCachePath.IsExtant() {
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

	http.ServeFile(rw, r, pCachePath.Render())
}
