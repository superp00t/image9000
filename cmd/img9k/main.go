package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/jpeg"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/superp00t/etc"

	"github.com/NYTimes/gziphandler"

	"github.com/c2h5oh/datasize"
	"github.com/gorilla/mux"
	"github.com/superp00t/etc/yo"
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
	EncryptedFileLifetime    int64 `json:"encrypted_file_lifetime_minutes"`

	AbuseReportURL string `json:"abuse_report_url"`
}

func (c Configuration) GetLifetime() time.Duration {
	return time.Duration(c.EncryptedFileLifetime) * time.Minute
}

type IndexPage struct {
	Config         template.JS
	AbuseReportURL string
	ShowImage      bool
	AcceptedTypes  string
	ImageURL       string
	SassyRemark    string
	Stamp          string
	FilesUploaded  int
	TotalSize      string
}

type RateLimitReq struct {
	IP string
	Ok chan bool
}

func IP(r *http.Request) string {
	var ip string
	if !Config.UseXRealIP {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	} else {
		ip = r.Header.Get("X-Real-IP")
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

func Mp3(buf []byte) bool {
	return len(buf) > 2 &&
		((buf[0] == 0x49 && buf[1] == 0x44 && buf[2] == 0x33) ||
			(buf[0] == 0xFF && buf[1] == 0xfb))
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := IP(r)

		if Config.LogHTTPRequests {
			yo.Printf("%s (%s) %s %s\n", ip, r.UserAgent(), r.Method, r.URL)
		}

		handler.ServeHTTP(w, r)
	})
}

func UploadHandler(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		ip := IP(r)
		ok := make(chan bool)

		HitFromIP <- RateLimitReq{
			IP: ip,
			Ok: ok,
		}

		okay := <-ok

		if !okay {
			Debug(ip + " is posting too much. Rate limiting!")
			rw.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(rw, "Your IP (%s) has uploaded too many files recently. Please wait and try again.", ip)
			return
		}

		r.ParseForm()
		r.ParseMultipartForm(Config.MaxSize)
		file, fileData, err := r.FormFile("file")

		if err != nil {
			hterr(rw, err)
			return
		}

		FileType := fileData.Header.Get("Content-Type")

		encrypted := strings.HasSuffix(fileData.Filename, ".i9k")

		if strings.HasSuffix(fileData.Filename, ".i9k") && r.URL.Query().Get("x") != "1" {
			hterr(rw, fmt.Errorf("you cannot upload this type"))
			return
		}

		if r.ContentLength > Config.MaxSize {
			http.Error(rw, "File Too big!", http.StatusRequestEntityTooLarge)
			return
		}

		var rd io.Reader = file
		ext := Config.AcceptedFmt[FileType]

		// Not actually an encrypted blob.
		if !encrypted && ext == "i9k" {
			ext = "bin"
		}

		if strings.HasPrefix(FileType, "text/xml") && ext != "svg" {
			http.Error(rw, "invalid XML", http.StatusBadRequest)
			return
		}

		if ext == "svg" {
			fileBuf := etc.NewBuffer()
			io.Copy(fileBuf, file)
			if strings.Contains(fileBuf.ToString(), "<script") || strings.Contains(fileBuf.ToString(), "onload") {
				yo.Warn("potential XSS from ", IP(r))
				http.Error(rw, "potential XSS exploit detected", http.StatusBadRequest)
				hterr(rw, fmt.Errorf("potential XSS exploit detected"))
				return
			}
			rd = fileBuf
		}

		if ext == "" {
			Debug("Filetype " + FileType + " not supported")
			hterr(rw, fmt.Errorf("File type (%s) not supported.", FileType))
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
				hterr(rw, fmt.Errorf("Text type (%s) not supported.", ext))
				return
			}
		}

		if FileType == "image/jpeg" {
			Debug("JPEG detected, re-encoding to remove harmful metadata")
			img, err := jpeg.Decode(rd)
			if err != nil {
				hterr(rw, err)
				return
			}

			out := etc.NewBuffer()

			err = jpeg.Encode(out, img, &jpeg.Options{Quality: 90})
			if err != nil {
				hterr(rw, err)
				return
			}
			rd = out
		}

		id := CreateFileId(ext)

		diskfile, err := etc.FileController(directory.Concat("i", id).Render())
		if err != nil {
			panic(err)
		}

		tmpBuffer := make([]byte, int(4*datasize.MB))

		_, err = io.CopyBuffer(diskfile, rd, tmpBuffer)
		if err != nil {
			yo.Warn(err)
			hterr(rw, fmt.Errorf("Could not write your file. Perhaps the server ran out of storage space."))
			return
		}

		http.Redirect(rw, r, Config.Subpath+id, 301)
	default:
		http.Error(rw, "Bad Request", http.StatusBadRequest)
	}
}

func Debug(str string) {
	if Config.Debug {
		yo.Println(str)
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

	enumer := ""

	for _, v := range acc[:len(acc)-1] {
		enumer += v + ", "
	}

	enumer += acc[len(acc)-1]

	rand.Seed(time.Now().UTC().UnixNano())

	t := loadTpl("index.html")

	result.SassyRemark = Config.SassyRemarks[rand.Intn(len(Config.SassyRemarks))]
	result.AcceptedTypes = enumer

	var filenames []string

	files := readImgDir()

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

	totalSize := int64(0)

	for _, i := range files {
		if i.IsDir() == false {
			totalSize += i.Size()
		}
	}

	result.TotalSize = datasize.ByteSize(totalSize).HumanReadable()

	arr, _ := json.Marshal(Config.AcceptedTextFmt)
	afm, _ := json.Marshal(Config.AcceptedFmt)

	result.Config = template.JS(fmt.Sprintf("{maxFileSize:%d,acceptedTextFmt:%s,acceptedFmt:%s}", Config.MaxSize, arr, afm))
	result.AbuseReportURL = Config.AbuseReportURL
	result.Stamp = fmt.Sprintf("%v", time.Since(start))
	result.FilesUploaded = len(files)
	exe(t, rw, result)
}

type proxyWriter struct {
	w io.Writer
}

func (p *proxyWriter) Write(b []byte) (int, error) {
	ln := len(b)
	n := []byte{}

	for _, v := range b {
		if v != '\t' && v != '\n' && v != '\r' {
			n = append(n, v)
		}
	}

	_, err := p.w.Write(n)
	return ln, err
}

func exe(t *template.Template, w io.Writer, v interface{}) {
	pw := &proxyWriter{w}

	t.Execute(pw, v)
}

var directory etc.Path

func main() {
	yo.AddSubroutine("run", []string{"directory"}, "a terribly engineered file hosting service.", srvMain)
	yo.Init()
}

func srvMain(args []string) {
	dir := ""
	if args[0] == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			yo.Fatal(err)
		}
	} else {
		dir = args[0]
	}

	directory = etc.ParseSystemPath(dir)
	if !directory.IsExtant() {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			yo.Fatal(err)
		}
	}

	b64Encoding = base64.NewEncoding(b64)

	if directory.Exists("config.json") == false {
		data, _ := Asset("assets/config.json")

		yo.Ok("No config.json found, creating...")

		err := ioutil.WriteFile(directory.Concat("config.json").Render(), data, 0700)
		if err != nil {
			yo.Fatal(err)
		}
	}

	cdat, err := ioutil.ReadFile(directory.Concat("config.json").Render())
	if err != nil {
		yo.Fatal("You need a config.json file to run this site.")
	}

	err = json.Unmarshal(cdat, &Config)
	if err != nil {
		yo.Fatal(err)
	}

	imageExt, err = regexp.Compile("(?i).(jpg|jpeg|png|gif)$")
	if err != nil {
		yo.Fatal(err)
	}

	if !directory.Exists("i") {
		yo.Ok("No i directory found. Creating...")
		if err := os.MkdirAll(directory.Concat("i").Render(), 0700); err != nil {
			yo.Fatal(err)
		}
	}

	go sweep()
	go RateLimiter()

	r := mux.NewRouter()
	r.HandleFunc("/", IndexHTML)
	r.HandleFunc("/index.html", IndexHTML)
	r.HandleFunc("/upload", UploadHandler)

	// Serve files
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(assetFS())))

	iserver := gziphandler.GzipHandler(http.FileServer(http.Dir(directory.Concat("i").Render())))

	r.PathPrefix("/i/").Handler(http.StripPrefix("/i/", iserver))
	is := new(_iserver)
	is.relay = iserver
	r.PathPrefix("/{thing}").Handler(is)

	yo.Printf("Listening at %s\n", Config.Listen)
	yo.Fatal(http.ListenAndServe(Config.Listen, Log(r)))
}

type VisitorData struct {
	Archive bool   `json:"archive"`
	Content string `json:"content"`
}

type VisitorPage struct {
	Filename string
	Metadata template.JS
}

type _iserver struct {
	relay http.Handler
}

func (i *_iserver) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	thing := mux.Vars(r)["thing"]
	yo.Ok(thing)

	if strings.Contains(thing, "/") || strings.Contains(thing, "..") {
		return
	}

	if directory.Concat("i").Exists(thing) == false {
		yo.Warn("Thing", thing, "does not exist")
		http.Error(rw, "404 not found", 404)
		return
	}

	if ext := filepath.Ext(thing); ext != "" {
		yo.Ok("Filtering ext", ext)
		switch ext {
		case ".i9k":
			i.openVisitor(rw, r, VisitorData{Content: thing})
			return
		case ".gz", ".zip":
			i.openVisitor(rw, r, VisitorData{Content: thing, Archive: true})
			return
		}
	}

	i.relay.ServeHTTP(rw, r)
}

func loadTpl(name string) *template.Template {
	tpl, _ := Asset("assets/" + name)
	t, err := template.New("").Parse(string(tpl))
	if err != nil {
		panic(err)
	}

	return t
}

func (i *_iserver) openVisitor(rw http.ResponseWriter, r *http.Request, data VisitorData) {
	encoded, _ := json.Marshal(data)
	t := loadTpl("visitor.html")
	exe(t, rw, VisitorPage{
		Filename: data.Content,
		Metadata: template.JS(encoded),
	})
}

func hterr(rw http.ResponseWriter, err error) {
	rw.WriteHeader(400)
	rw.Write([]byte(err.Error()))
}

func sweep() {
	for {
		dirs := readImgDir()

		for _, dir := range dirs {
			if strings.HasSuffix(dir.Name(), ".i9k") {
				if time.Since(dir.ModTime()) > Config.GetLifetime() {
					err := os.Remove(directory.Concat("i", dir.Name()).Render())
					if err != nil {
						yo.Fatal(err)
					}
				}
			}
		}

		time.Sleep(120 * time.Second)
	}
}

func readImgDir() []os.FileInfo {
	dir := directory.Concat("i", "").Render()
	yo.Warn("reading directory", dir)

	for {
		dirs, err := ioutil.ReadDir(dir)
		if err != nil {
			if err.Error() == "readdirent: no such file or directory" {
				yo.Warn(err)
				continue
			}
		}

		return dirs
	}
}
