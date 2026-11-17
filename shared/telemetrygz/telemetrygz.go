// Package telemetrygz is the gzip encoding of host agent telemetry batches
// (CommandAck.payload of "ebpf:telemetry:v2"): Encode on the
// host agent, DeclaredSize and Inflate on the control plane. Both sides live
// here so that everything Encode produces is accepted (TestEncodeIsAccepted).
//
// A member is one gzip member (RFC 1952) whose trailer declares the batch's
// size (ISIZE). The control plane charges that size to the sender's receive
// budget before inflating, so the declared size has to be paid for on the
// wire: a member may declare at most MaxRatio times its own length. Without
// the cap a member of ±8 KB declared 8 MiB (zeros, deflate's 1032:1), and an
// account charged 8 MiB per 8 KB counted toward the process-wide fair share
// for a thousandth of the bandwidth the share stands for.
//
// Real batches stay below the cap: 4–20× for ordinary traffic, 43–62× for
// floods of near-identical events (demo host and
// TestEncodeRealisticBatchesNeedNoPadding). Exact duplicates (±150×) and
// events with long repeated strings, such as a process opening a path of
// 4,000 identical characters (230–415×), go above it; Encode then pads the
// member with empty stored deflate blocks until it is 1/MaxRatio of the
// batch. Those blocks inflate to nothing, so the batch, its checksum and its
// declared size are unchanged and a control plane without the cap reads it
// as before. A batch is never dropped for its ratio.
package telemetrygz

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	// MaxBatchBytes caps a batch's declared (inflated) size at what an
	// uncompressed batch may be (the control plane's MaxRecvMsgSize).
	MaxBatchBytes = 8 << 20
	// MaxRatio caps the declared size of a member at this many times its
	// length.
	MaxRatio = 64
	// gzipTrailer: CRC-32 and ISIZE, written by Close.
	gzipTrailer = 8
)

// ErrMalformed: a member that is not valid gzip, declares more than
// MaxBatchBytes or MaxRatio times its length, or inflates to another size
// than it declares.
var ErrMalformed = errors.New("malformed compressed telemetry payload")

var writers = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}

// Encode returns body as one gzip member: deflated, and padded (padded true)
// when deflate alone would shrink it more than MaxRatio times. For a body of
// at most MaxBatchBytes, DeclaredSize accepts the member. An error means the
// body has to be sent uncompressed.
func Encode(body []byte) (gz []byte, padded bool, err error) {
	gz, err = deflate(body, 0)
	if err != nil {
		return nil, false, err
	}
	if withinRatio(len(body), len(gz)) {
		return gz, false, nil
	}
	gz, err = deflate(body, minLen(len(body)))
	if err != nil {
		return nil, false, err
	}
	if !withinRatio(len(body), len(gz)) {
		return nil, false, ErrMalformed // unreachable: deflate pads to minLen
	}
	return gz, true, nil
}

// deflate gzips body into a member of at least minSize bytes: after the
// data it adds empty stored blocks (each Flush writes one, 5 bytes) until
// the member, with its trailer, is that long.
func deflate(body []byte, minSize int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(max(len(body)/4, minSize) + 64)
	w := writers.Get().(*gzip.Writer)
	defer writers.Put(w)
	w.Reset(&buf)
	if _, err := w.Write(body); err != nil {
		return nil, err
	}
	for buf.Len()+gzipTrailer < minSize {
		before := buf.Len()
		if err := w.Flush(); err != nil {
			return nil, err
		}
		if buf.Len() == before {
			return nil, ErrMalformed // a flush that writes nothing would loop forever
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// minLen is the shortest member that may declare n bytes.
func minLen(n int) int { return (n + MaxRatio - 1) / MaxRatio }

func withinRatio(declared, length int) bool { return declared <= MaxRatio*length }

// DeclaredSize is the inflated size a member declares in its trailer (ISIZE,
// RFC 1952: the size modulo 2^32); ok is false when it is past MaxBatchBytes
// or past MaxRatio times the member's length.
func DeclaredSize(gz []byte) (int, bool) {
	if len(gz) < 18 { // 10-byte header + 8-byte trailer
		return 0, false
	}
	n := binary.LittleEndian.Uint32(gz[len(gz)-4:])
	if n > MaxBatchBytes {
		return 0, false // also keeps int(n) non-negative on 32-bit builds
	}
	if !withinRatio(int(n), len(gz)) {
		return 0, false
	}
	return int(n), true
}

// Inflate inflates a member that declares n bytes (DeclaredSize) into
// exactly n bytes with a valid checksum; anything else is ErrMalformed. The
// output is allocated before the content is validated: the caller has paid
// for n already.
func Inflate(gz []byte, n int) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, ErrMalformed
	}
	zr.Multistream(false)
	out := make([]byte, n)
	if _, err := io.ReadFull(zr, out); err != nil {
		return nil, ErrMalformed
	}
	// Reading past the declared size must hit the end of the member, where
	// gzip checks the CRC and size.
	var one [1]byte
	if k, err := zr.Read(one[:]); k != 0 || !errors.Is(err, io.EOF) {
		return nil, ErrMalformed
	}
	return out, nil
}
