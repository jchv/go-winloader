package winloader

import (
	"github.com/jchv/go-winloader/internal/memloader"
	"github.com/jchv/go-winloader/internal/winloader"
)

var ldr = memloader.New(memloader.Options{
	Next:    winloader.Loader{},
	Machine: winloader.NativeMachine{},
})

// LoadFromMemory loads a Windows module from memory.
func LoadFromMemory(data []byte) (Module, error) {
	return ldr.LoadMem(data)
}
