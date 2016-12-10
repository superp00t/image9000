# Image Uploader 9000!

Freakin' terrible image uploader. Written in Go.

### Building

`
go build 9000server.go
`
### Running the server

~~~~
Usage of ./9000server:
  -addr string
    	host:port format IP address to listen on (default "localhost:8000")
  -debug
    	show additional information about what is going on in the server.
  -logrequests
    	print all HTTP requests to stdout
  -maxSize int
    	the maximum size in bytes a user is allowed to upload (default 20971520)
  -random-img
    	display a random image in the folder in the main page (be careful: could be porn)
  -rateLimit int
    	the amount of files a user is allowed to upload per minute. (default 8)
  -subpath string
    	configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/) (default "/")
  -use-X-Real-IP
    	use the X-Real-IP header, useful for rate limiting behind a reverse proxy.
~~~~
