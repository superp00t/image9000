package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
	"strings"

)

var maxSize = flag.Int64("maxSize", 20971520, "the maximum size in bytes a user is allowed to upload")
var addr = flag.String("addr", "localhost:8000", "host:port format IP address to listen on")
var subpath = flag.String("subpath", "/", "configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/)")
var logrequests = flag.Bool("logrequests", false, "print all HTTP requests to stdout")
var rateLimit = flag.Int("rateLimit", 8, "the amount of files a user is allowed to upload per minute.")

var acceptedfmt = map[string]string{
	"image/jpeg":       "jpg",
	"image/png":        "png",
	"image/gif":        "gif",
	"video/webm":       "webm",
	"video/x-matroska": "mkv",
	"video/mp4":	    "mp4",
	"video/ogg":        "ogv",
	"application/ogg":  "ogg",
	"audio/ogg":        "ogg",
	"audio/mp3":        "mp3",
}


var postsPerMinute map[string]int

func RateLimiter() {
	for {
		postsPerMinute = make(map[string]int)
		time.Sleep(60 * time.Second)
	}
}

func CreateFileId(bt []byte, ext string) string {
	bytes := sha256.Sum256(bt)
	sha := hex.EncodeToString(bytes[:])
	return sha[:14] + "." + ext
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *logrequests {
			fmt.Printf("%s (%s) %s %s\n", r.RemoteAddr, r.UserAgent(), r.Method, r.URL)
		}

		handler.ServeHTTP(w, r)
	})
}

func UploadHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		ip := strings.Split(r.RemoteAddr, ":")[0]

		if postsPerMinute[ip] >= *rateLimit {
			if *logrequests {
				fmt.Println(ip + " is posting too much. Rate limiting!")
			}

			http.Redirect(rw, r, *subpath+"calm_down.html", 301)
			return
		}

		postsPerMinute[ip]++

		r.ParseForm()
		r.ParseMultipartForm(*maxSize)
		file, _, _ := r.FormFile("file")

		if r.ContentLength > *maxSize {
			http.Error(rw, "File Too big!", http.StatusRequestEntityTooLarge)
			return
		}

		var ImageBuf bytes.Buffer

		io.Copy(&ImageBuf, file)

		ImageBuffer := ImageBuf.Bytes()
		ImageType := http.DetectContentType(ImageBuffer)

		if acceptedfmt[ImageType] != "" {
			id := CreateFileId(ImageBuffer, acceptedfmt[ImageType])

			if _, err := os.Stat("web/img/" + id); os.IsNotExist(err) {
				err = ioutil.WriteFile("web/img/"+id, ImageBuffer, 0666)
				if err != nil {
					panic(err)
				}
			}

			http.Redirect(rw, r, *subpath+"img/"+id, 301)
		} else {
			http.Error(rw, fmt.Sprintf("File type (%s) not supported.", ImageType), http.StatusBadRequest)
		}
	default:
		http.Error(rw, "Bad Request", http.StatusBadRequest)
	}
}

func main() {
	flag.Parse()

	if _, err := os.Stat("web/img"); os.IsNotExist(err) {
		os.Mkdir("web/img", 0666)
	}

	go RateLimiter()

	http.Handle("/", http.FileServer(http.Dir("web")))

	http.HandleFunc("/upload", UploadHandler)
	http.ListenAndServe(*addr, Log(http.DefaultServeMux))

}
