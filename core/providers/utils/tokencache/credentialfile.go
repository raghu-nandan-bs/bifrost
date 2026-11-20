package tokencache

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CredentialDirsEnv lists, comma separated, the directories a workload credential file (an
// identity or subject token) may be read from, replacing DefaultCredentialDirs. It is read from
// the environment only, never from a key, so whoever can edit a key cannot have Bifrost read an
// arbitrary local file and send it out.
const CredentialDirsEnv = "BIFROST_OIDC_ALLOWED_CREDENTIAL_DIRS"

// DefaultCredentialDirs are the standard container credential mounts, where Kubernetes projects
// service account tokens.
var DefaultCredentialDirs = []string{"/var/run/secrets", "/run/secrets"}

// ErrCredentialPathNotAllowed is returned for a credential file outside the allowed directories.
var ErrCredentialPathNotAllowed = errors.New("outside the allowed credential directories")

// ErrCredentialFileNotRegular and ErrCredentialFileTooLarge are returned for a credential file
// that is not a regular file or exceeds the size limit. Both are faults in the configured path,
// not a mount that has yet to appear.
var (
	ErrCredentialFileNotRegular = errors.New("is not a regular file")
	ErrCredentialFileTooLarge   = errors.New("exceeds the size limit")
)

// allowedRoots returns the allowed credential directories, absolute and cleaned, each as
// written and with its own symlinks resolved, so both the configured path and the real path of
// a file under it match (/var/run is a link to /run on most distributions).
func allowedRoots() []string {
	dirs := DefaultCredentialDirs
	if raw := os.Getenv(CredentialDirsEnv); strings.TrimSpace(raw) != "" {
		dirs = strings.Split(raw, ",")
	}
	roots := make([]string, 0, 2*len(dirs))
	for _, dir := range dirs {
		if dir = strings.TrimSpace(dir); !filepath.IsAbs(dir) {
			continue
		}
		dir = filepath.Clean(dir)
		roots = append(roots, dir)
		if real, err := filepath.EvalSymlinks(dir); err == nil && real != dir {
			roots = append(roots, real)
		}
	}
	return roots
}

// hasDotDot reports whether path has a .. component. Such a path is refused rather than
// cleaned: when a is a symlink, a/../token need not name the same file as token.
func hasDotDot(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// checkPath refuses a credential path that is relative or has a .. component.
func checkPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", path)
	}
	if hasDotDot(path) {
		return fmt.Errorf("%s has a .. component; name the credential file without one (%w)", path, ErrCredentialPathNotAllowed)
	}
	return nil
}

func notAllowed(path string) error {
	return fmt.Errorf("%s is %w; set %s to the directories to read from, comma separated (default %s)",
		path, ErrCredentialPathNotAllowed, CredentialDirsEnv, strings.Join(DefaultCredentialDirs, ","))
}

// rootFor returns the allowed directory path sits under and path relative to it. Callers refuse
// .. components first (checkPath), so cleaning path here does not change the file it names.
func rootFor(path string) (string, string, bool) {
	clean := filepath.Clean(path)
	for _, root := range allowedRoots() {
		if rel, err := filepath.Rel(root, clean); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return root, rel, true
		}
	}
	return "", "", false
}

// CheckCredentialPath reports, without touching the file, whether ReadCredentialFile would
// accept path as written: absolute, with no .. component, and under an allowed credential
// directory. It is the save-time check, so the operator sees a refusal when the key is saved
// rather than on its first request, and a file that is not mounted yet still passes. A refusal
// wraps ErrCredentialPathNotAllowed, except for a relative path. It says nothing about where
// symlinks lead, so it must never be followed by a plain open: read the file through
// ReadCredentialFile, which re-checks the real path and opens it without a check-then-open race.
func CheckCredentialPath(path string) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if _, _, ok := rootFor(path); !ok {
		return notAllowed(path)
	}
	return nil
}

// errEscapesRoot marks an open that os.Root refused because a symlink leads out of the root.
var errEscapesRoot = errors.New("path escapes the credential directory")

// openInRoot opens rel, read only and without blocking on a FIFO, through an os.Root on dir.
func openInRoot(dir, rel string) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil && strings.Contains(err.Error(), "path escapes from parent") {
		return nil, errEscapesRoot
	}
	return f, err
}

// openResolved opens the real path of path, read only and without blocking on a FIFO, once that
// real path is known to sit under an allowed directory. A real path outside them is
// errEscapesRoot.
func openResolved(path string) (*os.File, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if _, _, ok := rootFor(resolved); !ok {
		return nil, errEscapesRoot
	}
	return os.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// ReadCredentialFile reads a credential file from an allowed directory, trimmed, refusing an
// empty file and one larger than maxBytes. The file is opened through an os.Root on the
// allowed directory, so no path component, symlink included, can lead out of it even if the
// directory changes between the check and the open. A directory that grants search but not read
// permission falls back to a resolve-and-recheck open (see the comment there). The open does not
// block on a FIFO, and the opened descriptor must be a regular file.
func ReadCredentialFile(path string, maxBytes int) (string, error) {
	if err := checkPath(path); err != nil {
		return "", err
	}
	rootDir, rel, ok := rootFor(path)
	if !ok {
		return "", notAllowed(path)
	}
	f, err := openInRoot(rootDir, rel)
	if errors.Is(err, errEscapesRoot) {
		// os.Root refuses every absolute symlink, even one whose target is inside an allowed
		// directory. Resolve the path and open the target, again through an os.Root on the
		// allowed directory it sits under, so a target outside every allowed directory, or a
		// link swapped after the resolve, is still refused.
		resolved, rerr := filepath.EvalSymlinks(path)
		if rerr != nil {
			return "", rerr
		}
		if rootDir, rel, ok = rootFor(resolved); !ok {
			return "", notAllowed(path)
		}
		f, err = openInRoot(rootDir, rel)
	}
	if errors.Is(err, fs.ErrPermission) {
		// os.Root opens the allowed directory and every directory under it for reading, so a
		// mount that grants only search permission (0711, read by a non-root Bifrost) is
		// refused although a plain open, which needs only search, reads the file. Fall back to
		// resolving the path, re-checking the real path against the allowed directories, and
		// opening that. This trades os.Root's guarantee for a
		// narrow window: a directory swapped for a symlink between the resolve and the open can
		// still redirect the read. Reaching it needs write access inside the allowed directory,
		// and the old reader had the same window on every read. A file the process cannot read
		// fails the plain open with the same error.
		f, err = openResolved(path)
	}
	if errors.Is(err, errEscapesRoot) {
		return "", notAllowed(path)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s %w", path, ErrCredentialFileNotRegular)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxBytes {
		return "", fmt.Errorf("%s %w of %d bytes", path, ErrCredentialFileTooLarge, maxBytes)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}
