package bloom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
)

const (
	bloomMagic   uint64 = 0x574146494F424C4D // "WAFIOBLM"
	bloomVersion uint32 = 1
)

// Filter is a concurrent-safe read, high-performance in-memory Bloom Filter.
type Filter struct {
	m     uint64   // Number of bits
	k     uint32   // Number of hash functions
	n     uint64   // Number of items added
	words []uint64 // Underlying bitset
}

// NewFilter creates a Bloom filter with capacity for expectedItems and target false positive rate p.
// Typical p = 0.0001 (0.01% false positive).
func NewFilter(expectedItems int, fpRate float64) *Filter {
	if expectedItems <= 0 {
		expectedItems = 1000
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.0001 // default 0.01%
	}

	n := float64(expectedItems)
	// m = - (n * ln(p)) / (ln(2)^2)
	m := math.Ceil(-1 * (n * math.Log(fpRate)) / (math.Ln2 * math.Ln2))
	if m < 64 {
		m = 64
	}
	// k = (m / n) * ln(2)
	k := math.Round((m / n) * math.Ln2)
	if k < 1 {
		k = 1
	}
	if k > 30 {
		k = 30
	}

	numWords := (uint64(m) + 63) / 64
	return &Filter{
		m:     uint64(m),
		k:     uint32(k),
		words: make([]uint64, numWords),
	}
}

// hashPair generates two independent 64-bit hashes h1 and h2 using Kirsch-Mitzenmacher optimization.
func hashPair(data []byte) (uint64, uint64) {
	if len(data) >= 16 {
		h1 := binary.LittleEndian.Uint64(data[0:8])
		h2 := binary.LittleEndian.Uint64(data[8:16])
		if h2 == 0 {
			h2 = 0x9e3779b97f4a7c15 // Golden ratio constant
		}
		return h1, h2
	}

	// For data < 16 bytes, use FNV-1a with two distinct seed salts
	f1 := fnv.New64a()
	f1.Write(data)
	h1 := f1.Sum64()

	f2 := fnv.New64()
	f2.Write(data)
	f2.Write([]byte{0xde, 0xad, 0xbe, 0xef})
	h2 := f2.Sum64()
	if h2 == 0 {
		h2 = 0x9e3779b97f4a7c15
	}
	return h1, h2
}

// Add inserts data into the Bloom filter.
func (f *Filter) Add(data []byte) {
	h1, h2 := hashPair(data)
	m := f.m
	k := f.k

	for i := uint32(0); i < k; i++ {
		idx := (h1 + uint64(i)*h2) % m
		f.words[idx/64] |= 1 << (idx % 64)
	}
	f.n++
}

// ItemsCount returns the number of items added to this filter.
func (f *Filter) ItemsCount() uint64 {
	return f.n
}

// BitsCount returns total number of bits in the filter.
func (f *Filter) BitsCount() uint64 {
	return f.m
}

// EstimatedFPRate returns the theoretical false positive rate given current item count n.
func (f *Filter) EstimatedFPRate() float64 {
	if f.m == 0 || f.n == 0 {
		return 0
	}
	// p = (1 - e^(-k*n/m))^k
	exponent := -float64(f.k) * float64(f.n) / float64(f.m)
	return math.Pow(1.0-math.Exp(exponent), float64(f.k))
}

// WriteTo serializes the Bloom filter into an io.Writer.
func (f *Filter) WriteTo(w io.Writer) (int64, error) {
	header := make([]byte, 28)
	binary.LittleEndian.PutUint64(header[0:8], bloomMagic)
	binary.LittleEndian.PutUint32(header[8:12], bloomVersion)
	binary.LittleEndian.PutUint32(header[12:16], f.k)
	binary.LittleEndian.PutUint64(header[16:24], f.m)
	binary.LittleEndian.PutUint32(header[24:28], uint32(len(f.words)))

	var total int64
	n, err := w.Write(header)
	total += int64(n)
	if err != nil {
		return total, err
	}

	buf := make([]byte, 8)
	for _, word := range f.words {
		binary.LittleEndian.PutUint64(buf, word)
		n, err := w.Write(buf)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	// Write item count
	binary.LittleEndian.PutUint64(buf, f.n)
	n, err = w.Write(buf)
	total += int64(n)
	return total, err
}

// ReadFrom deserializes a Bloom filter from an io.Reader.
func ReadFrom(r io.Reader) (*Filter, error) {
	header := make([]byte, 28)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	magic := binary.LittleEndian.Uint64(header[0:8])
	if magic != bloomMagic {
		return nil, errors.New("invalid bloom filter magic header")
	}

	version := binary.LittleEndian.Uint32(header[8:12])
	if version != bloomVersion {
		return nil, fmt.Errorf("unsupported bloom filter version: %d", version)
	}

	k := binary.LittleEndian.Uint32(header[12:16])
	m := binary.LittleEndian.Uint64(header[16:24])
	wordCount := binary.LittleEndian.Uint32(header[24:28])

	if k == 0 || k > 30 || m == 0 || m > 128*1024*1024*8 || uint64(wordCount) != (m+63)/64 {
		return nil, errors.New("invalid or oversized Bloom geometry")
	}
	words := make([]uint64, wordCount)
	buf := make([]byte, 8)
	for i := uint32(0); i < wordCount; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("read word %d: %w", i, err)
		}
		words[i] = binary.LittleEndian.Uint64(buf)
	}

	var itemCount uint64
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read item count: %w", err)
	}
	itemCount = binary.LittleEndian.Uint64(buf)

	return &Filter{
		m:     m,
		k:     k,
		n:     itemCount,
		words: words,
	}, nil
}
