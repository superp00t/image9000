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
	"path/filepath"
	"regexp"
	"sort"
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
	"image/jpeg":                "jpg",
	"image/png":                 "png",
	"image/gif":                 "gif",
	"video/webm":                "webm",
	"video/x-matroska":          "mkv",
	"video/mp4":                 "mp4",
	"video/ogg":                 "ogv",
	"application/ogg":           "ogg",
	"audio/ogg":                 "ogg",
	"audio/mp3":                 "mp3",
	"audio/mpeg":                "mp3",
	"text/plain; charset=utf-8": "txt",
}

var acceptedTextFmt = []string{
	"css",
	"obj",
	"js",
	"json",
	"xml",
	"txt",
	"sh",
	"lua",
	"go",
}

var SassyRemarks = []string{
	"hello darkness my old friend",
	"don't complain if this doesn't work",
	"i'm only human, I too make horrible mistakes",
	"dear god make it stop",
	"this clearly isn't professional",
	"holy fuck this uploader sucks",
	"remember to stop uploading every now and again. uploading for extended periods is unhealthy",
	"if this doesn't work please open an issue on github",
}

var postsPerMinute map[string]int

type Req struct {
	r *http.Request
}

type IndexPage struct {
	ShowImage     bool
	AcceptedTypes []string
	ImageURL      string
	SassyRemark   string
	Stamp         string
}

type rateLimitNotificationPage struct {
	IP    string
	Limit int
}

func (req *Req) IP() string {
	var ip string
	if !*useXRealIP {
		ip = strings.Split(req.r.RemoteAddr, ":")[0]
	} else {
		ip = req.r.Header.Get("X-Real-IP")
	}
	return ip
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
		ipr := Req{r}
		ip := ipr.IP()

		if *logrequests {
			fmt.Printf("%s (%s) %s %s\n", ip, r.UserAgent(), r.Method, r.URL)
		}

		handler.ServeHTTP(w, r)
	})
}

func UploadHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		ipr := Req{r}
		ip := ipr.IP()

		if postsPerMinute[ip] >= *rateLimit {
			Debug(ip + " is posting too much. Rate limiting!")

			http.Redirect(rw, r, *subpath+"ratelimit", 301)
			return
		}

		postsPerMinute[ip]++

		r.ParseForm()
		r.ParseMultipartForm(*maxSize)
		file, fileData, err := r.FormFile("file")

		if err != nil {
			http.Error(rw, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}

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

		var ext string
		ext = acceptedfmt[FileType]
		if ext == "" {
			Debug("Filetype " + FileType + " not supported")
			http.Error(rw, fmt.Sprintf("File type (%s) not supported.", FileType), http.StatusBadRequest)
			return
		}

		if FileType == "text/plain; charset=utf-8" {
			ext = filepath.Ext(fileData.Filename)[1:]
			okay := false

			for _, validExt := range acceptedTextFmt {
				if ext == validExt {
					okay = true
					break
				}
			}

			if !okay {
				Debug("Text type " + ext + " not supported")
				http.Error(rw, fmt.Sprintf("Text type (%s) not supported.", ext), http.StatusBadRequest)
				return
			}
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

		id := CreateFileId(FileBuf.Bytes(), ext)

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

func rateLimitNotification(rw http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("pages/ratelimit.html")
	if err != nil {
		log.Fatal(err)
	}

	ipr := Req{r}
	ip := ipr.IP()

	t.Execute(rw, rateLimitNotificationPage{
		IP:    ip,
		Limit: *rateLimit,
	})
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
	http.HandleFunc("/ratelimit", rateLimitNotification)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("web"))))
	http.Handle("/i/", http.StripPrefix("/i/", http.FileServer(http.Dir("i"))))

	http.HandleFunc("/upload", UploadHandler)
	log.Printf("Listening at %s\n", *addr)
	err = http.ListenAndServe(*addr, Log(http.DefaultServeMux))
	if err != nil {
		log.Fatal(err)
	}
}

func Debug(str string) {
	if *debug {
		fmt.Println(str)
	}
}

func IndexHTML(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var acc []string
	var result IndexPage
	encounter := make(map[string]bool)
	for _, tfmt := range acceptedfmt {
		if !encounter[tfmt] {
			acc = append(acc, tfmt)
		}

		encounter[tfmt] = true
	}

	for _, tfmt := range acceptedTextFmt {
		if !encounter[tfmt] {
			acc = append(acc, tfmt)
		}

		encounter[tfmt] = true
	}

	sort.Strings(acc)

	rand.Seed(time.Now().UTC().UnixNano())

	t, err := template.ParseFiles("pages/index.html")
	if err != nil {
		log.Fatal(err)
	}

	result.SassyRemark = SassyRemarks[rand.Intn(len(SassyRemarks))]
	result.AcceptedTypes = acc

	var filenames []string

	files, err := ioutil.ReadDir("i/")
	if err != nil {
		log.Fatal(err)
	}

	if *showRandomImage {
		for _, file := range files {
			if imageExt.MatchString(file.Name()) && file.Size() < 800000 {
				filenames = append(filenames, file.Name())
			}
		}

		if len(filenames) == 0 {
			result.ShowImage = false
		} else {
			result.ShowImage = true
			result.ImageURL = filenames[rand.Intn(len(filenames))]
		}
	} else {
		result.ShowImage = false
	}

	result.Stamp = fmt.Sprintf("%v | %d files uploaded", time.Since(start), len(files))
	t.Execute(rw, result)
}
