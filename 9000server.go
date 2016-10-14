package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var maxSize = flag.Int64("maxSize", 20971520, "the maximum size in bytes a user is allowed to upload")
var addr = flag.String("addr", "localhost:8000", "host:port format IP address to listen on")
var subpath = flag.String("subpath", "", "configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/)")
var logrequests = flag.Bool("logrequests", false, "print all HTTP requests to stdout")

func GenerateToken() string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
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
			fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		}
		handler.ServeHTTP(w, r)
	})
}

func ImageHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		matched, err := regexp.MatchString(`^[a-zA-Z0-9_]*$`, r.URL.Query().Get("i"))
		if err != nil {
			log.Fatal(err)
		}

		if !matched {
			http.Error(rw, "Bad Request", http.StatusBadRequest)
			return
		}

		bytes, err := ioutil.ReadFile("img/" + r.URL.Query().Get("i"))
		if err != nil {
			http.Error(rw, "File Not Found", http.StatusNotFound)
			return
		}

		ImageType := http.DetectContentType(bytes)
		rw.Header().Set("Content-Type", ImageType)
		rw.Write(bytes)

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
		if strings.HasPrefix(ImageType, "image/") {
			err = ioutil.WriteFile("img/"+id, ImageBuffer, 0666)
			if err != nil {
				panic(err)
			}

			http.Redirect(rw, r, *subpath+"/img?i="+id, 301)
		} else {
			http.Error(rw, fmt.Sprintf("File type (%s) not supported.", ImageType), http.StatusBadRequest)
		}
	}
}

func main() {
	flag.Parse()

	if _, err := os.Stat("img"); os.IsNotExist(err) {
		os.Mkdir("img", 0666)
	}

	http.Handle("/", http.FileServer(http.Dir("web")))
	http.HandleFunc("/img", ImageHandler)
	http.ListenAndServe(*addr, Log(http.DefaultServeMux))
}
