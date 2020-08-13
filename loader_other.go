// +build !windows

package winloader

import "fmt"

// LoadFromMemory loads a Windows module from memory.
func LoadFromMemory(data []byte) (Module, error) {
	return nil, fmt.Errorf("unsupported platform")
}
