package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
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

const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!"

var (
	b64Encoding    *base64.Encoding
	imageExt       *regexp.Regexp
	postsPerMinute map[string]int64
	Config         Configuration
	HitFromIP      = make(chan RateLimitReq)
)

type Configuration struct {
	AcceptedFmt     map[string]string `json:"accepted_fmt"`
	AcceptedTextFmt []string          `json:"accepted_text_fmt"`

	SassyRemarks []string `json:"sassy_remarks"`
	Subpath      string   `json:"subpath"`
	Listen       string   `json:"listen"`

	MaxSize int64 `json:"max_file_size"`

	UseXRealIP      bool `json:"use_X-Real-IP_header"`
	Debug           bool `json:"debug"`
	ShowRandomImage bool `json:"random_img"`

	LogHTTPRequests          bool  `json:"log_http_requests"`
	RateLimitUploadCount     int64 `json:"rate_limit_count"`
	RateLimitIntervalSeconds int64 `json:"rate_limit_interval_seconds"`
}

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
	Limit int64
}

type RateLimitReq struct {
	IP string
	Ok chan bool
}

func (req *Req) IP() string {
	var ip string
	if !Config.UseXRealIP {
		ip = strings.Split(req.r.RemoteAddr, ":")[0]
	} else {
		ip = req.r.Header.Get("X-Real-IP")
	}

	return ip
}

func RateLimiter() {
	go func() {
		for {
			select {
			case req := <-HitFromIP:
				postsPerMinute[req.IP]++

				req.Ok <- postsPerMinute[req.IP] <= Config.RateLimitUploadCount
			}
		}
	}()

	// from time to time, erase the map to perform rate-limiting
	for {
		postsPerMinute = make(map[string]int64)
		time.Sleep(time.Duration(Config.RateLimitIntervalSeconds) * time.Second)
	}
}

func RandomString(leng int) string {
	buf := make([]byte, leng)
	crand.Read(buf)
	return b64Encoding.EncodeToString(buf)[:leng]
}

func Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

func CreateFileId(ext string) string {
	for x := 4; ; x++ {
		fname := RandomString(x) + "." + ext
		if Exists(fname) {
			Debug("Filename collision detected. Retrying...")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return fname
	}
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipr := Req{r}
		ip := ipr.IP()

		if Config.LogHTTPRequests {
			log.Printf("%s (%s) %s %s\n", ip, r.UserAgent(), r.Method, r.URL)
		}

		handler.ServeHTTP(w, r)
	})
}

func UploadHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		ipr := Req{r}
		ip := ipr.IP()

		ok := make(chan bool)

		HitFromIP <- RateLimitReq{
			IP: ip,
			Ok: ok,
		}

		okay := <-ok

		if !okay {
			Debug(ip + " is posting too much. Rate limiting!")

			rw.WriteHeader(http.StatusTooManyRequests)

			t, err := template.ParseFiles("pages/ratelimit.html")
			if err != nil {
				log.Fatal(err)
			}

			t.Execute(rw, rateLimitNotificationPage{
				IP:    ip,
				Limit: Config.RateLimitUploadCount,
			})
			return
		}

		r.ParseForm()
		r.ParseMultipartForm(Config.MaxSize)
		file, fileData, err := r.FormFile("file")

		if err != nil {
			http.Error(rw, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}

		if r.ContentLength > Config.MaxSize {
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
		ext = Config.AcceptedFmt[FileType]
		if ext == "" {
			Debug("Filetype " + FileType + " not supported")
			http.Error(rw, fmt.Sprintf("File type (%s) not supported.", FileType), http.StatusBadRequest)
			return
		}

		if FileType == "text/plain; charset=utf-8" {
			ext = filepath.Ext(fileData.Filename)[1:]
			okay := false

			for _, validExt := range Config.AcceptedTextFmt {
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

		id := CreateFileId(ext)
		err = ioutil.WriteFile("i/"+id, FileBuf.Bytes(), 0666)
		if err != nil {
			log.Fatal(err)
		}

		http.Redirect(rw, r, Config.Subpath+"i/"+id, 301)
	default:
		http.Error(rw, "Bad Request", http.StatusBadRequest)
	}
}

func Debug(str string) {
	if Config.Debug {
		log.Println(str)
	}
}

func IndexHTML(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var acc []string
	var result IndexPage
	encounter := make(map[string]bool)
	for _, tfmt := range Config.AcceptedFmt {
		if !encounter[tfmt] {
			acc = append(acc, tfmt)
		}

		encounter[tfmt] = true
	}

	for _, tfmt := range Config.AcceptedTextFmt {
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

	result.SassyRemark = Config.SassyRemarks[rand.Intn(len(Config.SassyRemarks))]
	result.AcceptedTypes = acc

	var filenames []string

	files, err := ioutil.ReadDir("i/")
	if err != nil {
		log.Fatal(err)
	}

	if Config.ShowRandomImage {
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

func main() {
	b64Encoding = base64.NewEncoding(b64)

	cdat, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatal("You need a config.json file to run this site.")
	}

	err = json.Unmarshal(cdat, &Config)
	if err != nil {
		log.Fatal(err)
	}

	imageExt, err = regexp.Compile("(?i).(jpg|jpeg|png|gif)$")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat("i"); os.IsNotExist(err) {
		os.Mkdir("i", 0700)
	}

	go RateLimiter()

	http.HandleFunc("/", IndexHTML)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("web"))))
	http.Handle("/i/", http.StripPrefix("/i/", http.FileServer(http.Dir("i"))))

	http.HandleFunc("/upload", UploadHandler)
	log.Printf("Listening at %s\n", Config.Listen)
	err = http.ListenAndServe(Config.Listen, Log(http.DefaultServeMux))
	if err != nil {
		log.Fatal(err)
	}
}
