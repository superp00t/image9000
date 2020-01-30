package i9k

import (
	context "context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/ptypes"

	"github.com/superp00t/etc"

	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

const (
	// 3 megabytes
	MaxChunkSize = 3e+6
)

type File struct {
	Path string
	*os.File
}

// FileStorageServer can be embedded to have forward compatible implementations.
type FileStorageServer struct {
	Base        etc.Path
	Fingerprint string
}

// check identity of peer
func (fss *FileStorageServer) verify(ctx context.Context) error {
	fp, err := GetPeerFingerprint(ctx)
	if err != nil {
		return err
	}

	if fp != fss.Fingerprint {
		return err
	}

	return nil
}

func (fss *FileStorageServer) getSafeFilePath(path string) (etc.Path, error) {
	subPath := etc.ParseUnixPath(path)
	if len(subPath) < 1 {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid path")
	}

	if subPath[0] == "..." {
		return nil, status.Errorf(codes.InvalidArgument, "Must use relative paths")
	}

	safePath := fss.Base.GetSub(subPath)

	return safePath, nil
}

func (fss *FileStorageServer) statInfo(finf os.FileInfo) *StatResponse {
	tm, err := ptypes.TimestampProto(finf.ModTime())
	if err != nil {
		panic(err)
	}

	return &StatResponse{
		FileName:        finf.Name(),
		FileSize:        finf.Size(),
		FileMode:        uint32(finf.Mode()),
		FileModTime:     tm,
		FileIsDirectory: finf.IsDir(),
	}
}

func (fss *FileStorageServer) Stat(ctx context.Context, req *StatRequest) (*StatResponse, error) {
	if err := fss.verify(ctx); err != nil {
		return nil, err
	}
	safePath, err := fss.getSafeFilePath(req.Path)
	if err != nil {
		return nil, err
	}

	finf, err := os.Stat(safePath.Render())
	if err != nil {
		return nil, err
	}

	if finf.Size() == 0 {
		panic("invalid size")
	}

	sr := fss.statInfo(finf)

	return sr, nil
}

func (fss *FileStorageServer) WriteAll(srv Storage_WriteAllServer) error {
	if err := fss.verify(srv.Context()); err != nil {
		return err
	}

	var file *os.File

	for {
		data, err := srv.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		if file == nil {
			fh := data.GetFileName()
			if fh == "" {
				return status.Errorf(codes.InvalidArgument, "handle should be first element in stream")
			}

			filePath, err := fss.getSafeFilePath(fh)
			if err != nil {
				return err
			}

			if _, err = os.Stat(filePath.Render()); err == nil {
				os.Remove(filePath.Render())
			}

			file, err = os.OpenFile(filePath.Render(), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0700)
			if err != nil {
				panic(err)
			}
			continue
		}

		bytes := data.GetData()
		if bytes == nil {
			return status.Errorf(codes.InvalidArgument, "no data")
		}

		_, err = file.Write(bytes)
		if err != nil {
			return err
		}
	}

	srv.SendAndClose(&Empty{})
	return nil
}

func (fss *FileStorageServer) ReadAt(ctx context.Context, req *ReadAtRequest) (*ReadChunk, error) {
	if err := fss.verify(ctx); err != nil {
		return nil, err
	}

	path, err := fss.getSafeFilePath(req.Path)
	if err != nil {
		return nil, err
	}

	if req.Size > MaxChunkSize {
		return nil, err
	}

	file, err := os.OpenFile(path.Render(), os.O_RDONLY, 0700)
	if err != nil {
		return nil, err
	}

	if _, err := file.Seek(int64(req.StartOffset), 0); err != nil {
		return nil, err
	}

	data := make([]byte, req.Size)

	i, err := file.Read(data)
	if err != nil {
		return nil, err
	}

	return &ReadChunk{
		Data: data[:i],
	}, nil
}

func (fss *FileStorageServer) ListDirectory(ctx context.Context, req *Empty) (*DirectoryList, error) {
	if err := fss.verify(ctx); err != nil {
		return nil, err
	}

	var files []*DirectoryEnt

	if err := filepath.Walk(fss.Base.Render(), func(path string, finf os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if finf.IsDir() == false {
			files = append(files, &DirectoryEnt{
				Path: strings.Replace(path, fss.Base.Render(), "", 1),
				Size: finf.Size()})
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &DirectoryList{
		Results: files,
	}, nil
}
