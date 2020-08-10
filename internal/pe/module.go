package pe

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	// ErrBadMZSignature is returned when the MZ signature is invalid.
	ErrBadMZSignature = errors.New("mz: bad signature")

	// ErrBadPESignature is returned when the PE signature is invalid.
	ErrBadPESignature = errors.New("pe: bad signature")

	// ErrUnknownOptionalHeaderMagic is returned when the optional header
	// magic field has an unknown value.
	ErrUnknownOptionalHeaderMagic = errors.New("pe: unknown optional header magic")
)

// Module contains a parsed and loaded PE file.
type Module struct {
	hdr ImageNTHeaders64
}

// LoadModule loads a PE module into memory.
func LoadModule(r io.ReadSeeker) (*Module, error) {
	r.Seek(0, io.SeekStart)
	dos := ImageDOSHeader{}
	if err := binary.Read(r, binary.LittleEndian, &dos); err != nil {
		return nil, err
	}

	if dos.Signature != MZSignature {
		return nil, ErrBadMZSignature
	}

	r.Seek(int64(dos.NewHeaderAddr), io.SeekStart)
	pesig := [4]byte{}
	if err := binary.Read(r, binary.LittleEndian, &pesig); err != nil {
		return nil, err
	}

	if pesig != PESignature {
		return nil, ErrBadPESignature
	}

	optmagic := uint16(0)
	r.Seek(int64(dos.NewHeaderAddr)+OffsetOfOptionalHeaderMagicFromNTHeader, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &optmagic); err != nil {
		return nil, err
	}

	r.Seek(int64(dos.NewHeaderAddr), io.SeekStart)
	switch optmagic {
	case ImageNTOptionalHeader32Magic:
		return LoadModulePE32(r)
	case ImageNTOptionalHeader64Magic:
		return LoadModulePE64(r)
	default:
		return nil, ErrUnknownOptionalHeaderMagic
	}
}

// LoadModulePE32 loads a PE32 module into memory.
func LoadModulePE32(r io.ReadSeeker) (*Module, error) {
	nt := ImageNTHeaders32{}
	if err := binary.Read(r, binary.LittleEndian, &nt); err != nil {
		return nil, err
	}

	if nt.Signature != PESignature {
		return nil, ErrBadPESignature
	}

	m := &Module{}
	m.hdr = nt.To64()

	for i := uint16(0); i < nt.FileHeader.NumberOfSections; i++ {
		section := ImageSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, &section); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// LoadModulePE64 loads a PE64 module into memory.
func LoadModulePE64(r io.ReadSeeker) (*Module, error) {
	nt := ImageNTHeaders64{}
	if err := binary.Read(r, binary.LittleEndian, &nt); err != nil {
		return nil, err
	}

	if nt.Signature != PESignature {
		return nil, ErrBadPESignature
	}

	m := &Module{}
	m.hdr = nt

	for i := uint16(0); i < nt.FileHeader.NumberOfSections; i++ {
		section := ImageSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, &section); err != nil {
			return nil, err
		}
	}

	return m, nil
}
