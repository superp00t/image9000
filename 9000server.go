package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"
)

var maxSize = flag.Int64("maxSize", 20971520, "the maximum size in bytes a user is allowed to upload")
var addr = flag.String("addr", "localhost:8000", "host:port format IP address to listen on")
var subpath = flag.String("subpath", "/", "configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/)")
var logrequests = flag.Bool("logrequests", false, "print all HTTP requests to stdout")

var acceptedfmt = map[string]string{
	"image/jpeg":       "jpg",
	"image/png":        "png",
	"image/gif":        "gif",
	"video/webm":       "webm",
	"video/x-matroska": "mkv",
	"video/ogg":        "ogv",
	"application/ogg":  "ogg",
	"audio/ogg":        "ogg",
	"audio/mp3":        "ogv",
	"text/plain":       "txt",
}

func GenerateToken() string {
	const alphanum = "0123456789abcdefghijklmnopqrstuvwxyz"
	rand.Seed(time.Now().UTC().UnixNano())
	result := make([]byte, 14)
	for i := 0; i < 14; i++ {
		result[i] = alphanum[rand.Intn(len(alphanum))]
	}
	return string(result)
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
		r.ParseMultipartForm(*maxSize)
		file, _, _ := r.FormFile("file")
		if r.ContentLength > *maxSize {
			http.Error(rw, "File Too big!", http.StatusRequestEntityTooLarge)
			return
		}

		ImageReader := bufio.NewReader(file)
		ImageBuffer := make([]byte, r.ContentLength)
		_, err := ImageReader.Read(ImageBuffer)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		id := GenerateToken()
		ImageType := http.DetectContentType(ImageBuffer)
		if acceptedfmt[ImageType] != "" {
			err = ioutil.WriteFile("web/img/"+id+"."+acceptedfmt[ImageType], ImageBuffer, 0666)
			if err != nil {
				panic(err)
			}
			fmt.Println("redirecting to " + *subpath + "img/" + id + "." + acceptedfmt[ImageType])
			http.Redirect(rw, r, *subpath+"img/"+id+"."+acceptedfmt[ImageType], 301)
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

	http.Handle(*subpath, http.FileServer(http.Dir("web")))

	http.HandleFunc("/upload", UploadHandler)
	http.ListenAndServe(*addr, Log(http.DefaultServeMux))
}
