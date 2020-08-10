# go-winloader

**Note:** This is currently non-functional, check back soon.

go-winloader is a library that implements the Windows module loader algorithm in pure Go. The actual Windows module loader, accessible via `LoadLibrary`, only supports loading modules from disk, which is sometimes undesirable. With go-winloader, you can load modules directly from memory without needing to write intermediate temporary files to disk.

This is a bit more versatile than linking directly to object files, since you do not need object files for this approach. As a downside, it is a purely Windows-only approach.

## Example

```go
// Load a module off disk (for simplicity; you can pass in any io.ReadSeeker.)
mod, err := LoadLibrary(os.Open("my.dll"))
if err != nil {
    log.Fatalln("error loading module:", err)
}

// Get a procedure.
addProc := mod.GetProcAddress("_Add")
if proc == nil {
    log.Fatalln("module my.dll is missing required procedure _Add")
}

// Call the procedure!
result, _, _ := addProc.Call(1, 2)
log.Printf("1 + 2 = %d", result)
```
