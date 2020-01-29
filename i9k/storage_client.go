package i9k

import (
	context "context"
	fmt "fmt"
	"io"
	"os"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/superp00t/etc/yo"
)

func (s *StatResponse) Name() string {
	return s.GetFileName()
}

func (s *StatResponse) ModTime() time.Time {
	ts, _ := ptypes.Timestamp(s.FileModTime)
	return ts
}

func (s *StatResponse) Size() int64 {
	return s.GetFileSize()
}

func (s *StatResponse) Mode() os.FileMode {
	return os.FileMode(s.FileMode)
}

func (s *StatResponse) IsDir() bool {
	return s.FileIsDirectory
}

func (s *StatResponse) Sys() interface{} {
	return nil
}

type FileStorageClient struct {
	StorageClient
}

func (fsc *FileStorageClient) Overwrite(path string, size int64, reader io.Reader) error {
	wrAll, err := fsc.WriteAll(context.Background())
	if err != nil {
		panic(err)
		return err
	}

	if err := wrAll.Send(&WritePiece{
		PieceContent: &WritePiece_FileName{
			FileName: path,
		},
	}); err != nil {
		panic(err)
		return err
	}

	for lo := int64(0); lo < size; lo += MaxChunkSize {
		done := false
		hi := lo + MaxChunkSize
		if hi > size {
			hi = size
		}
		b := make([]byte, hi-lo)
		i, err := reader.Read(b)
		if err == io.EOF && size == (lo+int64(i)) {
			done = true
		} else {
			if err != nil {
				return fmt.Errorf("read error %d-%d (size: %d): %s", lo, hi, size, err)
			}
		}

		if err := wrAll.Send(&WritePiece{
			PieceContent: &WritePiece_Data{
				Data: b,
			},
		}); err != nil {
			return err
		}
		if done {
			break
		}
	}

	_, err = wrAll.CloseAndRecv()
	yo.Ok("closed and recieved")
	return err
}
