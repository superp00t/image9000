package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/superp00t/image9000/i9k"

	"github.com/superp00t/etc"
)

type filesystem interface {
	Overwrite(path string, size int64, reader io.Reader) error
	ReadBytesAt(path string, offset, size int64) ([]byte, error)
	CopyFileTo(path string, wr io.Writer) error
	Stat(path string) (os.FileInfo, error)
	List() ([]*i9k.DirectoryEnt, error)
}

type local struct {
	Base etc.Path
}

func (l *local) getSafePath(path string) (etc.Path, error) {
	e := etc.ParseUnixPath(path)
	if len(e) == 0 || e[0] == "..." {
		return nil, fmt.Errorf("invalid path")
	}

	return l.Base.GetSub(e), nil
}

func (l *local) Overwrite(paths string, size int64, reader io.Reader) error {
	path, err := l.getSafePath(paths)
	if err != nil {
		return err
	}

	os.Remove(path.Render())

	f, err := os.Create(path.Render())
	if err != nil {
		return err
	}

	_, err = io.Copy(f, reader)
	if err != nil {
		return err
	}

	return f.Close()
}

func (l *local) ReadBytesAt(paths string, offset, size int64) ([]byte, error) {
	path, err := l.getSafePath(paths)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path.Render(), os.O_RDONLY, 0700)
	if err != nil {
		return nil, err
	}

	if _, err := file.Seek(offset, 0); err != nil {
		return nil, err
	}

	data := make([]byte, size)

	_, err = file.Read(data)
	if err != nil {
		return nil, err
	}

	return data, file.Close()
}

func (l *local) Stat(paths string) (os.FileInfo, error) {
	path, err := l.getSafePath(paths)
	if err != nil {
		return nil, err
	}

	return os.Stat(path.Render())
}

func (l *local) CopyFileTo(paths string, wr io.Writer) error {
	path, err := l.getSafePath(paths)
	if err != nil {
		return err
	}

	file, err := os.Open(path.Render())
	if err != nil {
		return err
	}

	_, err = io.Copy(wr, file)
	if err != nil {
		return err
	}

	return file.Close()
}

func (l *local) List() ([]*i9k.DirectoryEnt, error) {
	var files []*i9k.DirectoryEnt

	filepath.Walk(l.Base.Render(), func(path string, finf os.FileInfo, err error) error {
		if finf.IsDir() == false {
			files = append(files, &i9k.DirectoryEnt{
				Path: strings.TrimPrefix(strings.Replace(path, l.Base.Render(), "", 1), string(os.PathSeparator)),
				Size: finf.Size()})
		}
		return nil
	})

	return files, nil
}

type filesystemReadSeeker struct {
	Size   int64
	Offset int64
	Path   string
}

func (f *filesystemReadSeeker) Seek(offset int64, whence int) (int64, error) {
	f.Offset = offset

	if whence == io.SeekEnd {
		return f.Size, nil
	}

	return 0, nil
}

func (f *filesystemReadSeeker) Read(b []byte) (int, error) {
	if f.Offset >= f.Size {
		return 0, io.EOF
	}

	content, err := fsystem.ReadBytesAt(f.Path, f.Offset, int64(len(b)))
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	copy(b, content)
	f.Offset += int64(len(content))
	return len(content), nil
}
