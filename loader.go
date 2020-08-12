package winloader

import (
	"errors"
)

// Proc represents a procedure on a Windows module.
type Proc interface {
	// Call calls the procedure. r1 and r2 contain the return value. lastErr
	// contains the Windows error value after calling.
	Call(a ...uintptr) (r1, r2 uintptr, lastErr error)
}

// Module represents a loaded Windows module.
type Module interface {
	// GetProcAddres returns a procedure by symbol name. Returns nil if the
	// symbol is not found.
	GetProcAddress(symbol string) Proc

	// Free closes the module and frees the memory. After this, GetProcAddress
	// will stop working and procedures will no longer function.
	Free() error
}

// LoadLibrary implements a Windows module loader. It accepts a byte slice
// of a Portable Executable formatted module and returns an interface to
// interact with the loaded module.
func LoadLibrary(module []byte) (Module, error) {
	return nil, errors.New("unimplemented")
}
