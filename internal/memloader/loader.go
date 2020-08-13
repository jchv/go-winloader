package memloader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jchv/go-winloader/internal/loader"
	"github.com/jchv/go-winloader/internal/pe"
	"github.com/jchv/go-winloader/internal/vmem"
)

// module implements a module for the memory loader.
type module struct {
	machine loader.Machine
	memory  loader.Memory
	pemod   *pe.Module
	exports *pe.ExportTable
}

// Proc implements loader.Module
func (m *module) Proc(name string) loader.Proc {
	addr := m.exports.Proc(name)
	if addr == 0 {
		return nil
	}
	return m.machine.MemProc(addr)
}

// Ordinal implements loader.Module
func (m *module) Ordinal(ordinal uint64) loader.Proc {
	addr := m.exports.Ordinal(uint16(ordinal))
	if addr == 0 {
		return nil
	}
	return m.machine.MemProc(addr)
}

// Free implements loader.Module
func (m *module) Free() error {
	// Execute entrypoint for detach.
	entry := m.machine.MemProc(m.memory.Addr() + uint64(m.pemod.Header.OptionalHeader.AddressOfEntryPoint))
	entry.Call(uint64(m.memory.Addr()), 0, 0)

	// Free memory.
	m.memory.Free()
	return nil
}

// Loader implements a memory loader for PE files.
type Loader struct {
	next    loader.Loader
	machine loader.Machine
}

// Options contains the options for creating a new memory loader.
type Options struct {
	// Next specifies the loader to use for recursing to resolve modules by name.
	Next loader.Loader

	// Machine specifies the machine the module should be loaded into.
	Machine loader.Machine
}

// New creates a new loader with the specified options.
func New(opts Options) loader.MemLoader {
	return &Loader{
		next:    opts.Next,
		machine: opts.Machine,
	}
}

// LoadMem implements the loader.MemLoader interface.
func (l *Loader) LoadMem(data []byte) (loader.Module, error) {
	bin, err := pe.LoadModule(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if !l.machine.IsArchitectureSupported(int(bin.Header.FileHeader.Machine)) {
		return nil, fmt.Errorf("image architecture not %04x not supported by this machine", bin.Header.FileHeader.Machine)
	}

	pageSize := l.machine.GetPageSize()
	imageSize := vmem.RoundUp(uint64(bin.Header.OptionalHeader.SizeOfImage), pageSize)

	// Try allocating on preferred address.
	mem := l.machine.Alloc(bin.Header.OptionalHeader.ImageBase, imageSize, vmem.MemCommit|vmem.MemReserve, vmem.PageReadWrite)

	// If this fails, allocate in arbitrary location.
	// Ensure within a 4GiB boundary.
	failedAllocs := []loader.Memory{}
	for mem == nil || mem.Addr()>>32 != (mem.Addr()+imageSize)>>32 {
		if mem != nil {
			failedAllocs = append(failedAllocs, mem)
		}
		if mem = l.machine.Alloc(0, imageSize, vmem.MemCommit|vmem.MemReserve, vmem.PageReadWrite); mem == nil {
			return nil, fmt.Errorf("allocation of %d bytes failed", imageSize)
		}
	}
	for _, i := range failedAllocs {
		i.Free()
	}

	realBase := mem.Addr()
	hdrsize := uint64(bin.Header.OptionalHeader.SizeOfHeaders)
	vmem.Alloc(realBase, hdrsize, vmem.MemCommit, vmem.PageReadWrite).Write(data[0:hdrsize])

	// Map sections into memory
	for _, section := range bin.Sections {
		addr := realBase + uint64(section.VirtualAddress)
		if section.SizeOfRawData == 0 {
			size := uint64(bin.Header.OptionalHeader.SectionAlignment)
			if size != 0 {
				vmem.Alloc(addr, size, vmem.MemCommit, vmem.PageReadWrite).Clear()
			}
		} else {
			sectionData := data[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData]
			vmem.Alloc(addr, uint64(section.SizeOfRawData), vmem.MemCommit, vmem.PageReadWrite).Write(sectionData)
		}
		// TODO: need to set Misc.PhysicalAddress?
	}

	// TODO: Detect native byte order for relocations.
	order := binary.LittleEndian
	machine := int(bin.Header.FileHeader.Machine)

	// Perform relocations
	relocs := pe.LoadBaseRelocs(bin, mem)
	if err := pe.Relocate(machine, relocs, uint64(realBase), bin.Header.OptionalHeader.ImageBase, mem, order); err != nil {
		return nil, err
	}

	// Perform runtime linking
	if err := pe.LinkModule(bin, mem, l.next); err != nil {
		return nil, err
	}

	// Set access flags.
	for _, section := range bin.Sections {
		executable := section.Characteristics&pe.ImageSectionCharacteristicsMemoryExecute != 0
		readable := section.Characteristics&pe.ImageSectionCharacteristicsMemoryRead != 0
		writable := section.Characteristics&pe.ImageSectionCharacteristicsMemoryWrite != 0
		protect := vmem.PageNoAccess
		switch {
		case !executable && !readable && !writable:
			protect = vmem.PageNoAccess
		case !executable && !readable && writable:
			protect = vmem.PageWriteCopy
		case !executable && readable && !writable:
			protect = vmem.PageReadOnly
		case !executable && readable && writable:
			protect = vmem.PageReadWrite
		case executable && !readable && !writable:
			protect = vmem.PageExecute
		case executable && !readable && writable:
			protect = vmem.PageExecuteWriteCopy
		case executable && readable && !writable:
			protect = vmem.PageExecuteRead
		case executable && readable && writable:
			protect = vmem.PageExecuteReadWrite
		}
		err := mem.Protect(uint64(section.VirtualAddress), uint64(section.SizeOfRawData), protect)
		if err != nil {
			return nil, err
		}
	}

	// Execute TLS callbacks.
	tlsdir := bin.Header.OptionalHeader.DataDirectory[pe.ImageDirectoryEntryTLS]
	if tlsdir.Size > 0 {
		mem.Seek(int64(tlsdir.VirtualAddress), io.SeekStart)
		dir := pe.ImageTLSDirectory64{}
		b := [8]byte{}
		psize := 4
		if bin.IsPE64 {
			psize = 8
			binary.Read(mem, binary.LittleEndian, &dir)
		} else {
			dir32 := pe.ImageTLSDirectory32{}
			binary.Read(mem, binary.LittleEndian, &dir32)
			dir = dir32.To64()
		}
		mem.Seek(int64(dir.AddressOfCallBacks), io.SeekStart)
		for {
			mem.Read(b[:psize])
			addr := binary.LittleEndian.Uint64(b[:])
			if addr == 0 {
				break
			}
			cb := l.machine.MemProc(realBase + addr)
			cb.Call(uint64(mem.Addr()), 1, 0)
		}
	}

	// Execute entrypoint for attach.
	entry := l.machine.MemProc(realBase + uint64(bin.Header.OptionalHeader.AddressOfEntryPoint))
	entry.Call(uint64(mem.Addr()), 1, 0)

	exports, err := pe.LoadExports(bin, mem, realBase)
	if err != nil {
		return nil, err
	}

	return &module{
		machine: l.machine,
		memory:  mem,
		pemod:   bin,
		exports: exports,
	}, nil
}
