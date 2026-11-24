//go:build ceph_luks_header_session

package rbd

// #cgo LDFLAGS: -lrbd
// #include <errno.h>
// #include <unistd.h>
// #include <rbd/librbd.h>
import "C"

import (
	"errors"
)

// ErrEncryptionLUKSHeaderClosed may be returned if an api call requires an
// open LUKS header session and the session was closed.
var ErrEncryptionLUKSHeaderClosed = errors.New("RBD LUKS header session is closed")

// EncryptionLUKSHeader is a session on a staged copy of the LUKS header of
// an image. The copy is a file that the caller changes, for example with
// libcryptsetup on /proc/self/fd/<fd>, and Commit writes back.
//
// The copy holds every keyslot in use, so it is as sensitive as the header
// itself. Close the session before the image is closed.
type EncryptionLUKSHeader struct {
	image  *Image
	header C.rbd_encryption_luks_header_t
	fd     C.int
}

// EncryptionLUKSHeaderOpen stages a copy of the LUKS header of the image
// and returns a session on it. The copy carries the LUKS magic even on a
// clone.
//
// Implements:
//
//	int rbd_encryption_luks_header_open(rbd_image_t image,
//	                                    rbd_encryption_luks_header_t *header,
//	                                    int *fd);
func (image *Image) EncryptionLUKSHeaderOpen() (*EncryptionLUKSHeader, error) {
	if err := image.validate(imageIsOpen); err != nil {
		return nil, err
	}

	var (
		header C.rbd_encryption_luks_header_t
		fd     C.int
	)
	ret := C.rbd_encryption_luks_header_open(image.image, &header, &fd)
	if ret != 0 {
		return nil, getError(ret)
	}

	return &EncryptionLUKSHeader{image: image, header: header, fd: fd}, nil
}

// Fd returns the file descriptor of the staged header. The descriptor
// belongs to the session and is closed by Close.
func (h *EncryptionLUKSHeader) Fd() uintptr {
	return uintptr(h.fd)
}

// Commit writes the staged header back to the image: the ranges that differ
// from the stored header, then one flush. Nothing is verified. A header
// with a moved data offset, or with data beyond it, is refused. A session
// can commit more than once.
//
// Commit does not call rbd_lock_acquire, so the caller decides how the
// exclusive lock is held during the commit:
//
//   - Without a lock call librbd takes the lock by itself for each write
//     and gives it up when another client asks for it, for example a VM
//     that writes to the image. That can happen between two writes, and
//     the header then stays half written until this client has the lock
//     back.
//   - With LockAcquire(LockModeExclusiveTransient) before Commit and
//     LockRelease after, the lock is kept for the whole commit and the
//     other client waits. This is the way for an image that is in use.
//   - With LockAcquire(LockModeExclusive) the lock is kept as well, but
//     the writes of the other client fail meanwhile.
//
// Only one session at a time may change the header of an image.
//
// Close a libcryptsetup handle on the file before the commit.
//
// Implements:
//
//	int rbd_encryption_luks_header_commit(rbd_encryption_luks_header_t header);
func (h *EncryptionLUKSHeader) Commit() error {
	if h.header == nil {
		return ErrEncryptionLUKSHeaderClosed
	}
	// librbd writes through the image of the session
	if err := h.image.validate(imageIsOpen); err != nil {
		return err
	}

	ret := C.rbd_encryption_luks_header_commit(h.header)
	return getError(ret)
}

// Close discards the staged copy and closes its file descriptor. Changes
// that were not committed are lost.
//
// Implements:
//
//	int rbd_encryption_luks_header_close(rbd_encryption_luks_header_t header);
func (h *EncryptionLUKSHeader) Close() error {
	if h.header == nil {
		return ErrEncryptionLUKSHeaderClosed
	}

	C.close(h.fd)
	h.fd = -1

	ret := C.rbd_encryption_luks_header_close(h.header)
	h.header = nil
	return getError(ret)
}
