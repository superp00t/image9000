# Image Uploader 9000!

What did you expect? It's just a simple image uploader. Don't look at me...

### Building

`
go build 9000server.go
`
### Running the server

~~~~
./9000server

Usage of ./9000server:
  -addr string
    	host:port format IP address to listen on (default "localhost:8000")
  -logrequests
    	print all HTTP requests to stdout
  -maxSize int
    	the maximum size in bytes a user is allowed to upload (default 20971520)
  -rateLimit int
    	the amount of files a user is allowed to upload per minute. (default 8)
  -subpath string
    	configure a subdirectory, for use with a reverse proxy (example: ./9000server -subpath=/image9000/) (default "/")
  -use-X-Real-IP
    	use the X-Real-IP header, useful for rate limiting behind a reverse proxy.
~~~~
