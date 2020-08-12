// +build !windows

package vmem

// Memory represents a raw block of memory.
type Memory struct {
	data []byte
}

// GetPageSize returns the size of a memory page.
func GetPageSize() int64 {
	panic("not implemented")
}

// Alloc allocates memory at addr of size with allocType and protect.
// It returns nil if it fails.
func Alloc(addr, size, allocType, protect uintptr) *Memory {
	panic("not implemented")
}

// Free frees the block of memory.
func (m *Memory) Free() {
	panic("not implemented")
}

// Read implements the io.Reader interface.
func (m *Memory) Read(b []byte) (n int, err error) {
	panic("not implemented")
}

// ReadAt implements the io.ReaderAt interface.
func (m *Memory) ReadAt(b []byte, off int64) (n int, err error) {
	panic("not implemented")
}

// Write implements the io.Writer interface.
func (m *Memory) Write(b []byte) (n int, err error) {
	panic("not implemented")
}

// WriteAt implements the io.WriterAt interface.
func (m *Memory) WriteAt(b []byte, off int64) (n int, err error) {
	panic("not implemented")
}

// Seek implements the io.Seeker interface.
func (m *Memory) Seek(offset int64, whence int) (int64, error) {
	panic("not implemented")
}
