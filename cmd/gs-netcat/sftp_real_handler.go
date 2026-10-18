// v0.2.5: sftpRootHandler methods.
//
// Implements the 4 SFTP handler interfaces required by pkg/sftp v1.13:
//   FileGet  = sftp.FileReader  (Fileread(*Request) (io.ReaderAt, error))
//   FilePut  = sftp.FileWriter  (Filewrite(*Request) (io.WriterAt, error))
//   FileCmd  = sftp.FileCmder   (Filecmd(*Request) error)
//   FileList = sftp.FileLister  (Filelist(*Request) (ListerAt, error))
package main

import (
        "errors"
        "io"
        "os"
        "path/filepath"
        "time"

        "github.com/pkg/sftp"
)

// fileReaderAt wraps *os.File to provide ReaderAt.
type fileReaderAt struct {
        f    *os.File
        off  int64 // current offset (sequential reads via ReadAt use this)
}

func (r *fileReaderAt) ReadAt(p []byte, off int64) (int, error) {
        return r.f.ReadAt(p, off)
}

// fileWriterAt wraps *os.File to provide WriterAt.
type fileWriterAt struct {
        f *os.File
}

func (w *fileWriterAt) WriteAt(p []byte, off int64) (int, error) {
        return w.f.WriteAt(p, off)
}

// Fileread implements sftp.FileReader (FileGet handler).
func (h *sftpRootHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
        path := h.resolve(r)
        if path == "" {
                return nil, errors.New("sftp: path resolution failed")
        }
        f, err := os.OpenFile(path, os.O_RDONLY, 0)
        if err != nil {
                return nil, err
        }
        return &fileReaderAt{f: f}, nil
}

// Filewrite implements sftp.FileWriter (FilePut handler).
func (h *sftpRootHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
        path := h.resolve(r)
        if path == "" {
                return nil, errors.New("sftp: path resolution failed")
        }
        flags := r.Pflags()
        mode := os.FileMode(0o644)
        if flags.Append {
                f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, mode)
                if err != nil {
                        return nil, err
                }
                if _, err := f.Seek(0, io.SeekEnd); err != nil {
                        f.Close()
                        return nil, err
                }
                return &fileWriterAt{f: f}, nil
        }
        f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
        if err != nil {
                return nil, err
        }
        return &fileWriterAt{f: f}, nil
}

// Filecmd implements sftp.FileCmder (FileCmd handler).
func (h *sftpRootHandler) Filecmd(r *sftp.Request) error {
        path := h.resolve(r)
        if path == "" {
                return errors.New("sftp: path resolution failed")
        }
        switch r.Method {
        case "Rename":
                dst := h.resolvePath(r.Target)
                return os.Rename(path, dst)
        case "Setstat":
                return nil
        case "Rmdir":
                return os.Remove(path)
        case "Remove":
                return os.Remove(path)
        case "Mkdir":
                return os.Mkdir(path, 0o755)
        case "Symlink":
                dst := h.resolvePath(r.Target)
                return os.Symlink(path, dst)
        default:
                return errors.New("sftp: unsupported filecmd method: " + r.Method)
        }
}

// Filelist implements sftp.FileLister (FileList handler).
func (h *sftpRootHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
        path := h.resolve(r)
        if path == "" {
                return nil, errors.New("sftp: path resolution failed")
        }
        switch r.Method {
        case "List":
                entries, err := os.ReadDir(path)
                if err != nil {
                        return nil, err
                }
                infos := make([]os.FileInfo, 0, len(entries))
                for _, e := range entries {
                        info, err := e.Info()
                        if err == nil {
                                infos = append(infos, info)
                        }
                }
                return listerAt(infos), nil
        case "Stat":
                info, err := os.Stat(path)
                if err != nil {
                        return nil, err
                }
                return listerAt([]os.FileInfo{info}), nil
        case "Readlink":
                target, err := os.Readlink(path)
                if err != nil {
                        return nil, err
                }
                info := &fakeFileInfo{name: target, isDir: false}
                return listerAt([]os.FileInfo{info}), nil
        default:
                return nil, errors.New("sftp: unsupported filelist method: " + r.Method)
        }
}

// resolve resolves the request path relative to root.
func (h *sftpRootHandler) resolve(r *sftp.Request) string {
        return h.resolvePath(r.Filepath)
}

// resolvePath resolves a path string relative to root.
func (h *sftpRootHandler) resolvePath(p string) string {
        if p == "" {
                return ""
        }
        cleaned := filepath.Clean(p)
        if filepath.IsAbs(cleaned) {
                cleaned = cleaned[1:] // strip leading /
        }
        return filepath.Join(h.root, cleaned)
}

// listerAt implements sftp.ListerAt.
type listerAt []os.FileInfo

func (l listerAt) ListAt(buf []os.FileInfo, offset int64) (int, error) {
        if offset >= int64(len(l)) {
                return 0, io.EOF
        }
        n := copy(buf, l[offset:])
        if n < len(buf) {
                return n, io.EOF
        }
        return n, nil
}

// fakeFileInfo is a minimal os.FileInfo implementation for Readlink.
type fakeFileInfo struct {
        name  string
        isDir bool
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64         { return 0 }
func (f *fakeFileInfo) Mode() os.FileMode   { return 0o777 }
func (f *fakeFileInfo) ModTime() time.Time   { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool          { return f.isDir }
func (f *fakeFileInfo) Sys() interface{}     { return nil }
