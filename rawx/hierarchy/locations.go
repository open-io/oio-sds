package hierarchy

import (
	"os"

	syscall "golang.org/x/sys/unix"
)

type Location struct {
	PathParentAbs string
	// FD of the repo to use as a base for
	FdBase int
	// path relative to the directory pointed to by FdBase
	relPath string
}

func (l *Location) Access(mode uint32) error {
	return syscall.Faccessat(l.FdBase, l.relPath, mode, 0)
}

func (l *Location) Open(flags int, mode uint32) (int, error) {
	fd, err := syscall.Openat(l.FdBase, l.relPath, flags, mode)
	if err != nil {
		return -1, err
	} else {
		return fd, nil
	}
}

func (l *Location) Unlink() error {
	return syscall.Unlinkat(l.FdBase, l.relPath, 0)
}

func (l *Location) LinkTo(locNew *Location) error {
	err := syscall.Linkat(l.FdBase, l.relPath, locNew.FdBase, locNew.relPath, 0)
	if err == nil {
		return nil
	}

	switch err.(syscall.Errno) {
	case syscall.ENOENT:
		// Slow path : need to create the target directory
		if e1 := os.MkdirAll(locNew.PathParentAbs, DirCreateMode); e1 != nil {
			return nil
		}
		return syscall.Linkat(l.FdBase, l.relPath, locNew.FdBase, locNew.relPath, 0)
	default:
		return err
	}
}

func (l *Location) RenameTo(locNew *Location) error {
	err := syscall.Renameat2(l.FdBase, l.relPath, locNew.FdBase, locNew.relPath, syscall.RENAME_NOREPLACE)

	switch err.(syscall.Errno) {
	case syscall.ENOENT:
		// Slow path : need to create the target directory. If the source directory doesn't exist,
		// no need to create it, because ENOENT is the correct answer
		if e1 := os.MkdirAll(locNew.PathParentAbs, DirCreateMode); e1 != nil {
			return nil
		}
		return syscall.Renameat2(l.FdBase, l.relPath, locNew.FdBase, locNew.relPath, syscall.RENAME_NOREPLACE)
	default:
		return err
	}
}

func (l *Location) Getattr(key string, value []byte) (int, error) {
	fd, err := l.Open(syscall.O_NOATIME|syscall.O_CLOEXEC|syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	return syscall.Fgetxattr(fd, key, value)
}

func (l *Location) Listattr(value []byte) (int, error) {
	fd, err := l.Open(syscall.O_NOATIME|syscall.O_CLOEXEC|syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	return syscall.Flistxattr(fd, value)
}

func (l *Location) Rmattr(key string) error {
	fd, err := l.Open(syscall.O_NOATIME|syscall.O_CLOEXEC|syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fremovexattr(fd, key)
}

func (l *Location) Setattr(key string, value []byte) error {
	fd, err := l.Open(syscall.O_NOATIME|syscall.O_CLOEXEC|syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fsetxattr(fd, key, value, 0)
}
