//go:build ceph_luks_header_session

package rbd

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openStagedHeader opens the staged file of a session the way libcryptsetup
// does, by path. The returned file is independent of the session's
// descriptor.
func openStagedHeader(t *testing.T, h *EncryptionLUKSHeader) *os.File {
	f, err := os.OpenFile(
		fmt.Sprintf("/proc/self/fd/%d", h.Fd()), os.O_RDWR, 0)
	require.NoError(t, err)
	return f
}

// copyStagedHeader copies the data of src over dst and leaves the holes
// of src alone, so that nothing is written beyond the header area.
func copyStagedHeader(t *testing.T, dst, src *os.File) {
	offset := int64(0)
	for {
		start, err := src.Seek(offset, unix.SEEK_DATA)
		if err != nil {
			// ENXIO: no data after offset
			break
		}
		end, err := src.Seek(start, unix.SEEK_HOLE)
		require.NoError(t, err)

		buf := make([]byte, end-start)
		_, err = src.ReadAt(buf, start)
		require.NoError(t, err)
		_, err = dst.WriteAt(buf, start)
		require.NoError(t, err)
		offset = end
	}
	require.NotZero(t, offset)
}

func assertErrorCode(t *testing.T, err error, errno syscall.Errno) {
	if !assert.Error(t, err) {
		return
	}
	if ec, ok := err.(interface{ ErrorCode() int }); assert.True(t, ok) {
		assert.Equal(t, -int(errno), ec.ErrorCode())
	}
}

func TestEncryptionLUKSHeader(t *testing.T) {
	conn := radosConnect(t)
	defer conn.Shutdown()

	poolname := GetUUID()
	err := conn.MakePool(poolname)
	require.NoError(t, err)
	defer conn.DeletePool(poolname)

	ioctx, err := conn.OpenIOContext(poolname)
	require.NoError(t, err)
	defer ioctx.Destroy()

	luks2 := func(passphrase string) EncryptionOptionsLUKS2 {
		return EncryptionOptionsLUKS2{
			Alg:        EncryptionAlgorithmAES256,
			Passphrase: []byte(passphrase),
		}
	}
	createImage := func(t *testing.T) string {
		name := GetUUID()
		options := NewRbdImageOptions()
		defer options.Destroy()
		require.NoError(t,
			options.SetUint64(ImageOptionOrder, uint64(testImageOrder)))
		require.NoError(t,
			CreateImage(ioctx, name, uint64(50)*1024*1024, options))
		return name
	}
	// the image is closed again, so that later handles have no encryption
	// loaded, like the handle of a caller that only changes the header
	createEncryptedImage := func(t *testing.T, passphrase string) string {
		name := createImage(t)
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		require.NoError(t, img.EncryptionFormat(luks2(passphrase)))
		require.NoError(t, img.Close())
		return name
	}
	loads := func(t *testing.T, name, passphrase string) error {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		return img.EncryptionLoad(luks2(passphrase))
	}

	name := createEncryptedImage(t, "first-passphrase")
	defer func() {
		assert.NoError(t, RemoveImage(ioctx, name))
	}()

	t.Run("stagedFile", func(t *testing.T) {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, hdr.Close())
		}()

		f := openStagedHeader(t, hdr)
		defer f.Close()
		// LUKS magic and version 2
		magic := make([]byte, 8)
		_, err = f.ReadAt(magic, 0)
		assert.NoError(t, err)
		assert.Equal(t, []byte("LUKS\xba\xbe\x00\x02"), magic)
	})

	t.Run("commitUnchanged", func(t *testing.T) {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, hdr.Close())
		}()

		assert.NoError(t, hdr.Commit())
		assert.NoError(t, hdr.Commit())
		assert.NoError(t, loads(t, name, "first-passphrase"))
	})

	// go-ceph has no libcryptsetup to change a keyslot with, so the
	// change is the whole header of a second image. Afterwards the image
	// loads with the passphrase of the second image only.
	t.Run("commitChanged", func(t *testing.T) {
		target := createEncryptedImage(t, "target-passphrase")
		defer func() {
			assert.NoError(t, RemoveImage(ioctx, target))
		}()
		donor := createEncryptedImage(t, "donor-passphrase")
		defer func() {
			assert.NoError(t, RemoveImage(ioctx, donor))
		}()

		func() {
			targetImg, err := OpenImage(ioctx, target, NoSnapshot)
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, targetImg.Close())
			}()
			donorImg, err := OpenImageReadOnly(ioctx, donor, NoSnapshot)
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, donorImg.Close())
			}()

			targetHdr, err := targetImg.EncryptionLUKSHeaderOpen()
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, targetHdr.Close())
			}()
			donorHdr, err := donorImg.EncryptionLUKSHeaderOpen()
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, donorHdr.Close())
			}()

			targetFile := openStagedHeader(t, targetHdr)
			defer targetFile.Close()
			donorFile := openStagedHeader(t, donorHdr)
			defer donorFile.Close()
			copyStagedHeader(t, targetFile, donorFile)

			// what the caller is asked to do around a commit
			require.NoError(t,
				targetImg.LockAcquire(LockModeExclusiveTransient))
			assert.NoError(t, targetHdr.Commit())
			assert.NoError(t, targetImg.LockRelease())
		}()

		assert.NoError(t, loads(t, target, "donor-passphrase"))
		assert.Error(t, loads(t, target, "target-passphrase"))
		assert.NoError(t, loads(t, donor, "donor-passphrase"))
	})

	t.Run("commitNoHeader", func(t *testing.T) {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, hdr.Close())
		}()

		// an empty file of the same size
		f := openStagedHeader(t, hdr)
		defer f.Close()
		info, err := f.Stat()
		require.NoError(t, err)
		require.NoError(t, f.Truncate(0))
		require.NoError(t, f.Truncate(info.Size()))

		assertErrorCode(t, hdr.Commit(), syscall.EINVAL)
		assert.NoError(t, loads(t, name, "first-passphrase"))
	})

	t.Run("commitReadOnly", func(t *testing.T) {
		img, err := OpenImageReadOnly(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, hdr.Close())
		}()

		assertErrorCode(t, hdr.Commit(), syscall.EROFS)
	})

	t.Run("closed", func(t *testing.T) {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)

		assert.NoError(t, hdr.Close())
		assert.Equal(t, ^uintptr(0), hdr.Fd())
		assert.ErrorIs(t, hdr.Commit(), ErrEncryptionLUKSHeaderClosed)
		assert.ErrorIs(t, hdr.Close(), ErrEncryptionLUKSHeaderClosed)
	})

	// the wrong order: the session can no longer commit, and is still
	// freed by Close
	t.Run("imageClosedFirst", func(t *testing.T) {
		img, err := OpenImage(ioctx, name, NoSnapshot)
		require.NoError(t, err)
		hdr, err := img.EncryptionLUKSHeaderOpen()
		require.NoError(t, err)

		require.NoError(t, img.Close())
		assert.ErrorIs(t, hdr.Commit(), ErrImageNotOpen)
		assert.NoError(t, hdr.Close())
	})

	t.Run("imageNotOpen", func(t *testing.T) {
		img := GetImage(ioctx, name)
		_, err := img.EncryptionLUKSHeaderOpen()
		assert.ErrorIs(t, err, ErrImageNotOpen)
	})

	t.Run("notEncrypted", func(t *testing.T) {
		plain := createImage(t)
		defer func() {
			assert.NoError(t, RemoveImage(ioctx, plain))
		}()
		img, err := OpenImage(ioctx, plain, NoSnapshot)
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, img.Close())
		}()

		_, err = img.EncryptionLUKSHeaderOpen()
		assert.Error(t, err)
	})
}
