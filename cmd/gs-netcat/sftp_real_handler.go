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
        "strings"
        "time"

        "github.com/pkg/sftp"
)

// fileReaderAt wraps *os.File to provide ReaderAt.
type fileReaderAt struct {
        f *os.File
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
//
// v0.3.0: Added chroot enforcement. The returned path is guaranteed to
// be inside h.root (after EvalSymlinks). Path traversal attempts
// (e.g. "../../etc/passwd" or "/etc/passwd") are clamped to h.root.
// Symlinks pointing outside h.root are also resolved to h.root.
//
// We use a two-step approach:
//   1. filepath.Clean the path + join to root (handles "../")
//   2. filepath.EvalSymlinks the result + check prefix (handles symlinks)
//
// If step 2 fails (file doesn't exist yet — e.g. for PUT), we check
// the parent directory's symlinks instead.
//
// Returns "" if the path could not be safely resolved.
func (h *sftpRootHandler) resolvePath(p string) string {
        if p == "" {
                return ""
        }
        // Step 1: clean + join to root.
        cleaned := filepath.Clean(p)
        if filepath.IsAbs(cleaned) {
                // Strip leading "/" so it's relative to root.
                cleaned = cleaned[1:]
        }
        joined := filepath.Join(h.root, cleaned)
        // filepath.Join already normalizes ".." away, but let's be defensive.
        if !filepath.IsAbs(joined) {
                abs, err := filepath.Abs(joined)
                if err == nil {
                        joined = abs
                }
        }

        // Step 2: EvalSymlinks. If the path exists, resolve it and verify
        // it's inside root.
        resolved, err := filepath.EvalSymlinks(joined)
        if err == nil {
                // Path exists — check prefix.
                if !isPathInside(resolved, h.root) {
                        // Symlink escaped root — clamp to root.
                        return h.root
                }
                return resolved
        }
        // Path doesn't exist (PUT case). Check the parent dir.
        parent := filepath.Dir(joined)
        resolvedParent, perr := filepath.EvalSymlinks(parent)
        if perr != nil {
                // Parent doesn't exist either — fall back to the joined path.
                return joined
        }
        if !isPathInside(resolvedParent, h.root) {
                return h.root
        }
        // Reconstruct: resolvedParent + base(joined).
        return filepath.Join(resolvedParent, filepath.Base(joined))
}

// isPathInside reports whether target is equal to or inside base.
// Both paths should be absolute and EvalSymlinks-resolved.
func isPathInside(target, base string) bool {
        if target == base {
                return true
        }
        // Ensure base ends with separator for prefix check.
        if len(base) > 0 && base[len(base)-1] != filepath.Separator {
                base = base + string(filepath.Separator)
        }
        return strings.HasPrefix(target, base)
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
