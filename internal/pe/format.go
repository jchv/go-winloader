package winloader

// Machine values for the file header.
const (
	ImageFileMachineUnknown    = 0x0000
	ImageFileMachineTargetHost = 0x0001
	ImageFileMachinei386       = 0x014c
	ImageFileMachineR3000      = 0x0162
	ImageFileMachineR4000      = 0x0166
	ImageFileMachineR10000     = 0x0168
	ImageFileMachineWCEMIPSv2  = 0x0169
	ImageFileMachineALPHA      = 0x0184
	ImageFileMachineSH3        = 0x01a2
	ImageFileMachineSH3DSP     = 0x01a3
	ImageFileMachineSH3E       = 0x01a4
	ImageFileMachineSH4        = 0x01a6
	ImageFileMachineSH5        = 0x01a8
	ImageFileMachineARM        = 0x01c0
	ImageFileMachineTHUMB      = 0x01c2
	ImageFileMachineARMNT      = 0x01c4
	ImageFileMachineAM33       = 0x01d3
	ImageFileMachinePowerPC    = 0x01F0
	ImageFileMachinePowerPCFP  = 0x01f1
	ImageFileMachineIA64       = 0x0200
	ImageFileMachineMIPS16     = 0x0266
	ImageFileMachineAlpha64    = 0x0284
	ImageFileMachineMIPSFPU    = 0x0366
	ImageFileMachineMIPSFPU16  = 0x0466
	ImageFileMachineAXP64      = ImageFileMachineAlpha64
	ImageFileMachineTricore    = 0x0520
	ImageFileMachineCEF        = 0x00CE
	ImageFileMachineEBC        = 0x0EBC
	ImageFileMachineAMD64      = 0x8664
	ImageFileMachineM32R       = 0x9041
	ImageFileMachineARM64      = 0xAA64
	ImageFileMachineCEE        = 0x0C0E
)

// Charateristics values for the file header.
const (
	ImageFileRelocsStripped       = 0x0001
	ImageFileExecutableImage      = 0x0002
	ImageFileLineNumsStripped     = 0x0004
	ImageFileLocalSymsStripped    = 0x0008
	ImageFileAggressiveWSTrim     = 0x0010
	ImageFileLargeAddressAware    = 0x0020
	ImageFileBytesReversedLo      = 0x0080
	ImageFile32BitMachine         = 0x0100
	ImageFileDebugStripped        = 0x0200
	ImageFileRemovableRunFromSwap = 0x0400
	ImageFileNetRunFromSwap       = 0x0800
	ImageFileSystem               = 0x1000
	ImageFileDLL                  = 0x2000
	ImageFileUPSystemOnly         = 0x4000
	ImageFileBytesReversedHi      = 0x8000
)

// ImageDOSHeader is the structure of the DOS MZ Executable format. All PE
// files contain at least a valid stub DOS MZ executable at the top; the PE
// format itself starts at the address specified by NewHeaderAddr.
type ImageDOSHeader struct {
	MagicNumber   uint16
	LastPageBytes uint16
	CountPages    uint16
	CountRelocs   uint16
	HeaderLen     uint16
	MinAlloc      uint16
	MaxAlloc      uint16
	InitialSS     uint16
	InitialSP     uint16
	Checksum      uint16
	InitialIP     uint16
	InitialCS     uint16
	RelocAddr     uint16
	OverlayNum    uint16
	Reserved      [4]uint16
	OEMID         uint16
	OEMInfo       uint16
	Reserved2     [10]uint16
	NewHeaderAddr uint32
}

// ImageBaseRelocation holds the header for a single page of base relocation
// data. The .reloc section of the binary contains a series of blocks of
// base relocation data, each starting with this header and followed by n
// 16-bit values that each represent a single relocation. The 4 most
// significant bits specify the type of relocation, while the 12 least
// significant bits contain the lower bits of the address (which is combined
// with the virtual address of the page.) The SizeOfBlock value specifies the
// size of an entire block, in bytes, including its header.
type ImageBaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// ImageDataDirectory holds a record for the given data directory. Each data
// directory contains information about another section, such as the import
// table. The index of the directory entry determines which section it
// pertains to.
type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// NumDirectoryEntries specifies the number of data directory entries.
const NumDirectoryEntries = 16

// MaxNumSections specifies the maximum number of sections that are allowed.
const MaxNumSections = 96

// ImageFileHeader contains some of the basic attributes about the PE/COFF
// file, including the number of sections and the machine type.
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// ImageOptionalHeader32 contains the optional header for 32-bit PE images. It
// is only 'optional' in the sense that not all PE/COFF binaries have it,
// however it is required for executables and DLLs.
type ImageOptionalHeader32 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32

	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [NumDirectoryEntries]ImageDataDirectory
}

// ImageOptionalHeader64 contains the optional header for 64-bit PE images.
type ImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [NumDirectoryEntries]ImageDataDirectory
}

// ImageNTHeaders32 contains the PE file headers for 32-bit PE images.
type ImageNTHeaders32 struct {
	// Signature identifies the PE format; Always "PE\0\0".
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader32
}

// ImageNTHeaders64 contains the PE file headers for 64-bit PE images.
type ImageNTHeaders64 struct {
	// Signature identifies the PE format; Always "PE\0\0".
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader64
}
