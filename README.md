# go-winloader

**Note:** This is currently experimental. It is *expected* that many Windows modules will not load at this time. Some architectures may not work entirely. If you would like to contribute fixes feel free, although I am actively working on this, so you may want to coordinate by opening an issue so we don't step on eachother's toes.

go-winloader is a library that implements the Windows module loader algorithm in pure Go. The actual Windows module loader, accessible via `LoadLibrary`, only supports loading modules from disk, which is sometimes undesirable. With go-winloader, you can load modules directly from memory without needing to write intermediate temporary files to disk.

This is a bit more versatile than linking directly to object files, since you do not need object files for this approach. As a downside, it is a purely Windows-only approach.

## Example

```go
// Load a module off disk (for simplicity; you can pass in any byte slice.)
b, _ := ioutil.ReadFile("my.dll")
mod, err := winloader.LoadFromMemory(b)
if err != nil {
    log.Fatalln("error loading module:", err)
}

// Get a procedure.
addProc := mod.Proc("Add")
if proc == nil {
    log.Fatalln("module my.dll is missing required procedure Add")
}

// Call the procedure!
result, _, _ := addProc.Call(1, 2)
log.Printf("1 + 2 = %d", result)
```
