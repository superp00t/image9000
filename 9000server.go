package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	imageExt        *regexp.Regexp
	maxSize         = flag.Int64("maxSize", 20971520, "the maximum size in bytes a user is allowed to upload")
	addr            = flag.String("addr", "localhost:8000", "host:port format IP address to listen on")
	subpath         = flag.String("subpath", "/", "configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/)")
	logrequests     = flag.Bool("logrequests", false, "print all HTTP requests to stdout")
	rateLimit       = flag.Int("rateLimit", 8, "the amount of files a user is allowed to upload per minute.")
	useXRealIP      = flag.Bool("use-X-Real-IP", false, "use the X-Real-IP header, useful for rate limiting behind a reverse proxy.")
	debug           = flag.Bool("debug", false, "show additional information about what is going on in the server.")
	showRandomImage = flag.Bool("random-img", false, "display a random image from the uploads folder in the main page (be careful:, could be porn)")
)

var acceptedfmt = map[string]string{
	"image/jpeg":       "jpg",
	"image/png":        "png",
	"image/gif":        "gif",
	"video/webm":       "webm",
	"video/x-matroska": "mkv",
	"video/mp4":        "mp4",
	"video/ogg":        "ogv",
	"application/ogg":  "ogg",
	"audio/ogg":        "ogg",
	"audio/mp3":        "mp3",
}

var SassyRemarks = []string{
	"hello darkness my old friend",
	"don't complain if this doesn't work",
	"i'm only human, I too make horrible mistakes",
	"dear god make it stop",
	"this clearly isn't professional",
	"holy fuck this uploader sucks",
}

var postsPerMinute map[string]int

type IndexPage struct {
	ShowImage   bool
	ImageURL    string
	SassyRemark string
}

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
		var ip string

		if !*useXRealIP {
			ip = strings.Split(r.RemoteAddr, ":")[0]
		} else {
			ip = r.Header.Get("X-Real-IP")
		}

		if *logrequests {
			fmt.Printf("%s (%s) %s %s\n", ip, r.UserAgent(), r.Method, r.URL)
		}

		handler.ServeHTTP(w, r)
	})
}

func UploadHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var ip string

		if !*useXRealIP {
			ip = strings.Split(r.RemoteAddr, ":")[0]
		} else {
			ip = r.Header.Get("X-Real-IP")
		}

		if postsPerMinute[ip] >= *rateLimit {
			Debug(ip + " is posting too much. Rate limiting!")

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

		var FileBuf bytes.Buffer

		wr, err := io.Copy(&FileBuf, file)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		FileType := http.DetectContentType(FileBuf.Bytes())

		Debug(fmt.Sprintf("%d bytes read type %s", wr, FileType))

		if acceptedfmt[FileType] == "" {
			Debug("Filetype " + FileType + " not supported")
			http.Error(rw, fmt.Sprintf("File type (%s) not supported.", FileType), http.StatusBadRequest)
			return
		}

		if FileType == "image/jpeg" {
			Debug("JPEG detected, re-encoding to remove harmful metadata")
			img, err := jpeg.Decode(&FileBuf)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}

			FileBuf = bytes.Buffer{}

			err = jpeg.Encode(&FileBuf, img, &jpeg.Options{Quality: 90})
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
		}

		id := CreateFileId(FileBuf.Bytes(), acceptedfmt[FileType])

		if _, err := os.Stat("i/" + id); os.IsNotExist(err) {
			Debug(id + " doesn't exist, writing...")
			err = ioutil.WriteFile("i/"+id, FileBuf.Bytes(), 0666)
			if err != nil {
				log.Fatal(err)
			}
		}

		http.Redirect(rw, r, *subpath+"i/"+id, 301)
	default:
		http.Error(rw, "Bad Request", http.StatusBadRequest)
	}
}

func main() {
	var err error
	imageExt, err = regexp.Compile("(?i).(jpg|jpeg|png|gif)$")
	if err != nil {
		log.Fatal(err)
	}

	flag.Parse()

	if _, err := os.Stat("i"); os.IsNotExist(err) {
		os.Mkdir("i", 0700)
	}

	go RateLimiter()

	http.HandleFunc("/", IndexHTML)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("web"))))
	http.Handle("/i/", http.StripPrefix("/i/", http.FileServer(http.Dir("i"))))

	http.HandleFunc("/upload", UploadHandler)
	http.ListenAndServe(*addr, Log(http.DefaultServeMux))

}

func Debug(str string) {
	if *debug {
		fmt.Println(str)
	}
}

func IndexHTML(rw http.ResponseWriter, r *http.Request) {
	rand.Seed(time.Now().UTC().UnixNano())

	t, err := template.ParseFiles("web/index.html")
	if err != nil {
		log.Fatal(err)
	}

	if *showRandomImage {
		files, err := ioutil.ReadDir("i/")

		if err != nil {
			log.Fatal(err)
		}

		var filenames []string

		for _, file := range files {
			if imageExt.MatchString(file.Name()) && file.Size() < 800000 {
				filenames = append(filenames, file.Name())
			}
		}

		if len(filenames) == 0 {
			t.Execute(rw, IndexPage{
				ShowImage:   false,
				SassyRemark: SassyRemarks[rand.Intn(len(SassyRemarks))],
			})

			return
		}

		t.Execute(rw, IndexPage{
			ShowImage:   true,
			SassyRemark: SassyRemarks[rand.Intn(len(SassyRemarks))],
			ImageURL:    filenames[rand.Intn(len(filenames))],
		})
	} else {
		t.Execute(rw, IndexPage{
			ShowImage:   false,
			SassyRemark: SassyRemarks[rand.Intn(len(SassyRemarks))],
		})
	}
}
