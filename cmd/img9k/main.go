package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/jpeg"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/superp00t/image9000/i9k"

	"github.com/superp00t/etc"

	"github.com/c2h5oh/datasize"
	"github.com/gorilla/mux"
	"github.com/superp00t/etc/yo"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/css"
	"github.com/tdewolff/minify/html"
	"github.com/tdewolff/minify/js"
	mjson "github.com/tdewolff/minify/json"
	"github.com/tdewolff/minify/svg"
)

const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!"

var (
	b64Encoding    *base64.Encoding
	imageExt       *regexp.Regexp
	postsPerMinute map[string]int64
	Config         Configuration
	HitFromIP      = make(chan RateLimitReq)
	fsystem        filesystem
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

	CacheDuration Duration `json:"cache_duration"`
	MaxCacheBytes uint64   `json:"max_cache_bytes"`

	Filesystem               string `json:"filesystem"`
	RemoteStorageServer      string `json:"remote_storage_server"`
	RemoteStorageFingerprint string `json:"remote_storage_fingerprint"`

	LocalStorage string `json:"local_storage"`

	AbuseReportURL string `json:"abuse_report_url"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) (err error) {
	d.Duration, err = time.ParseDuration(strings.Trim(string(b), `"`))
	return
}

func (d Duration) MarshalJSON() (b []byte, err error) {
	return []byte(fmt.Sprintf(`"%s"`, d.String())), nil
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
		err := r.ParseMultipartForm(Config.MaxSize)
		if err != nil {
			hterr(rw, err)
			return
		}

		files := r.MultipartForm.File["file"]
		if len(files) == 0 {
			hterr(rw, fmt.Errorf("no files"))
			return
		}

		if err != nil {
			hterr(rw, err)
			return
		}

		if len(files) > 2 {
			hterr(rw, fmt.Errorf("only one file allowed"))
			return
		}

		var rd io.Reader
		var size int64

		fileData := files[0]

		var file multipart.File
		// Allow Live Photos
		if len(files) > 1 {
			if files[0].Header.Get("Content-Type") == "image/jpeg" &&
				files[1].Header.Get("Content-Type") == "video/mov" {
				fileData = files[1]
				file, err = files[1].Open()
			}
		} else {
			file, err = files[0].Open()
		}
		if err != nil {
			hterr(rw, err)
			return
		}

		rd = file
		size = fileData.Size

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

		ext := Config.AcceptedFmt[FileType]

		// Not actually an encrypted blob.
		if !encrypted && ext == "i9k" {
			ext = "bin"
		}

		if ext == "" && strings.HasPrefix(FileType, "text/") {
			ext = "txt"
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
			size = fileBuf.Size()
		}

		if ext == "mov" {
			uidm := etc.TmpDirectory().Concat(etc.GenerateRandomUUID().String()).Render() + ".mov"
			outm := etc.TmpDirectory().Concat(etc.GenerateRandomUUID().String()).Render() + ".mp4"
			err2 := fmt.Errorf("could not write temporary mov")

			fi, err := etc.FileController(uidm)
			if err != nil {
				yo.Warn(err2, ":", err)
				hterr(rw, err2)
				return
			}

			io.Copy(fi, rd)
			fi.Close()

			defer os.Remove(uidm)

			c := exec.Command("ffmpeg", "-i", uidm, "-vcodec", "copy", "-acodec", "copy", outm)
			err = c.Run()
			if err != nil {
				yo.Warn("FFMPEG is not installed. Cannot convert mov")
				hterr(rw, fmt.Errorf("no FFMPEG installed"))
				return
			}

			read, err := etc.FileController(outm)
			if err != nil {
				yo.Warn(err2, ":", err)
				hterr(rw, err2)
				return
			}

			FileType = "video/mp4"
			ext = "mp4"

			defer read.Close()
			defer os.Remove(outm)

			rd = read
			size = read.Size()
		}

		if ext == "" {
			Debug("Filetype " + FileType + " not supported")
			hterr(rw, fmt.Errorf("File type (%s) not supported.", FileType))
			return
		}

		if strings.HasPrefix(FileType, "text/") {
			ext = filepath.Ext(fileData.Filename)[1:]
			okay := false

			for _, validExt := range Config.AcceptedTextFmt {
				if ext == validExt {
					okay = true
					break
				}
			}

			if !okay {
				ext = "txt"
			}
		}

		if FileType == "image/jpeg" {
			Debug("JPEG detected, re-encoding to remove harmful metadata")

			buffer := etc.NewBuffer()
			io.Copy(buffer, rd)

			cfg, err := jpeg.DecodeConfig(buffer)
			if err != nil {
				hterr(rw, err)
				return
			}

			if cfg.Height >= 8000 || cfg.Width >= 12000 {
				hterr(rw, fmt.Errorf("cannot upload large image like this"))
				return
			}

			buffer.SeekR(0)

			img, err := jpeg.Decode(buffer)
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
			size = out.Size()
			rd = out
		}

		id := CreateFileId(ext)

		err = fsystem.Overwrite(id, size, rd)
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
			if imageExt.MatchString(file.Path) && file.Size < 800000 {
				filenames = append(filenames, file.Path)
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
		totalSize += i.Size
	}

	result.TotalSize = datasize.ByteSize(totalSize).HumanReadable()

	arr, _ := json.Marshal(Config.AcceptedTextFmt)
	afm, _ := json.Marshal(Config.AcceptedFmt)

	result.Config = template.JS(fmt.Sprintf("{maxFileSize:%d,acceptedTextFmt:%s,acceptedFmt:%s}", Config.MaxSize, arr, afm))
	result.AbuseReportURL = Config.AbuseReportURL
	result.Stamp = fmt.Sprintf("%v", time.Since(start))
	result.FilesUploaded = len(files)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	idx := directory.Concat("c", "index")
	if idx.IsExtant() == false {
		data := execute(t, result)
		idx.WriteAll(data)
		rw.Write(data)
		return
	}

	if time.Since(idx.Time()) < 10*time.Second {
		dat, _ := idx.ReadAll()
		rw.Write(dat)
		return
	}

	data := execute(t, result)
	idx.WriteAll(data)
	rw.Write(data)
}

func exe(t *template.Template, rw http.ResponseWriter, v interface{}) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := execute(t, v)
	rw.Write(data)
}

func execute(t *template.Template, v interface{}) []byte {
	out := etc.NewBuffer()

	m := minify.New()
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("text/html", html.Minify)
	m.AddFunc("image/svg+xml", svg.Minify)
	m.AddFuncRegexp(regexp.MustCompile("^(application|text)/(x-)?(java|ecma)script$"), js.Minify)
	m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), mjson.Minify)

	wr := m.Writer("text/html", out)
	if err := t.Execute(wr, v); err != nil {
		yo.Fatal(err)
	}
	wr.Close()

	return out.Bytes()
}

var directory etc.Path

func main() {
	yo.AddSubroutine("run", []string{"directory"}, "a terribly engineered file hosting service.", srvMain)
	yo.AddSubroutine("storage", []string{"directory"}, "run a storage server", runStorage)
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

	if directory.Exists("cert.pem") == false {
		i9k.GenerateTLSKeyPair(directory.Render())
	}

	id, _ := i9k.GetCertFileFingerprint(directory.Concat("cert.pem").Render())

	certificates, err := tls.LoadX509KeyPair(
		directory.Concat("cert.pem").Render(),
		directory.Concat("key.pem").Render(),
	)

	if err != nil {
		yo.Fatal(err)
	}

	yo.Ok("Remote storage client fingerprint:", id)

	cdat, err := ioutil.ReadFile(directory.Concat("config.json").Render())
	if err != nil {
		yo.Fatal("You need a config.json file to run this site.")
	}

	err = json.Unmarshal(cdat, &Config)
	if err != nil {
		yo.Fatal(err)
	}

	if Config.MaxCacheBytes == 0 {
		Config.MaxCacheBytes = etc.MB * 850
	}

	if Config.CacheDuration.Duration == 0 {
		Config.CacheDuration.Duration = 24 * time.Hour
	}

	imageExt, err = regexp.Compile("(?i).(jpg|jpeg|png|gif)$")
	if err != nil {
		yo.Fatal(err)
	}

	switch Config.Filesystem {
	case "remote":
		rmt := &remote{}
		rmt.Certificate = certificates
		rmt.serverFingerprint = Config.RemoteStorageFingerprint
		gc, err := grpc.Dial(
			Config.RemoteStorageServer,
			grpc.WithInsecure(),
			grpc.WithContextDialer(rmt.dialContext),
		)
		if err != nil {
			panic(err)
		}

		rmt.FileStorageClient = &i9k.FileStorageClient{}
		rmt.FileStorageClient.StorageClient = i9k.NewStorageClient(gc)

		fsystem = rmt
	case "local":
		loc := &local{}
		if Config.LocalStorage == "" {
			loc.Base = directory.Concat("i")
		} else {
			lPath := etc.ParseSystemPath(Config.LocalStorage)
			if lPath[0] != "..." {
				loc.Base = lPath
			} else {
				loc.Base = directory.GetSub(lPath)
			}
		}

		if loc.Base.IsExtant() == false {
			yo.Ok("Creating", loc.Base.Render())
			loc.Base.MakeDir()
		}

		fsystem = loc
	default:
		yo.Fatal("unknown filesystem:", Config.Filesystem)
	}

	if !directory.Exists("i") {
		yo.Ok("No i directory found. Creating...")
		if err := os.MkdirAll(directory.Concat("i").Render(), 0700); err != nil {
			yo.Fatal(err)
		}
	}

	if !directory.Exists("c") {
		yo.Ok("No cache directory found. Creating...")
		directory.Concat("c").MakeDir()
	}

	go RateLimiter()

	r := mux.NewRouter()
	r.HandleFunc("/", IndexHTML)
	r.HandleFunc("/index.html", IndexHTML)
	r.HandleFunc("/upload", UploadHandler)

	// Serve files
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(assetFS())))

	iserver := &cacher{}

	// r.PathPrefix("/i/").Handler(http.StripPrefix("/i/", iserver))
	r.PathPrefix("/{thing}").Handler(iserver)

	yo.Printf("Listening at %s\n", Config.Listen)
	yo.Fatal(http.ListenAndServe(Config.Listen, Log(r)))
}

type VisitorData struct {
	Archive bool   `json:"archive"`
	Content string `json:"content"`
	Mime    string `json:"mime"`
}

type VisitorPage struct {
	Data     VisitorData
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
		vd := VisitorData{Content: thing}

		ct := "application/octet-stream"

		for k, v := range Config.AcceptedFmt {
			if v == ext[1:] {
				ct = k
			}
		}

		yo.Ok("Filtering ext", ext)

		vd.Mime = ct
		switch ext[1:] {
		case "i9k", "mp3", "ogg", "flac", "wav":
			i.openVisitor(rw, r, vd)
			return
		case "gz", "zip":
			vd.Archive = true
			i.openVisitor(rw, r, vd)
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
		Data:     data,
		Metadata: template.JS(encoded),
	})
}

func hterr(rw http.ResponseWriter, err error) {
	rw.WriteHeader(400)
	rw.Write([]byte(err.Error()))
}

func readImgDir() []*i9k.DirectoryEnt {
	dl, err := fsystem.List()
	if err != nil {
		return nil
	}

	return dl
}
