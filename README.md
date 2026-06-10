# __BETA:__ InnoUnp-Go: Pure Go Inno Setup Unpacker & Python API

A high-performance, cross-platform port of the legendary **Inno Setup Unpacker** (`innounp`) written in pure Go (Golang).

This platform supports **nearly three decades of Inno Setup installer structures** (from vintage v1.x releases in 1997 up to modern v6.x releases) natively under a unified, schema-driven, zero-dependency codebase. It is fully compiled as a command-line interface (CLI) and exposed as a high-performance, in-process **Python API wrapper** via ctypes.

> [!WARNING]
> **Active Testing & Beta Phase**
> This project is currently in its **active Beta and testing phase**. While our parsing coverage is extremely high and extensively validated against years of Inno Setup layouts, we are actively looking for feedback!
> If you encounter any custom-packed installers, obfuscation techniques, or edge cases where parsing fails, **please let us know and open an issue with the sample hash or error logs** so we can continue to expand and perfect our self-healing capabilities!

---

## 1. Codebase Structure

*   **`innounp-go/`** - The Go module home.
    *   **`parser/`** - The core extraction engine package:
        *   `loader.go` & `types.go`: PE binary DOS header scanners and 32/64-bit offset table solvers. Supports legacy and modern signatures.
        *   `compress.go`: Custom `CRCChunkReader` segment parser, alongside zlib, bzip2, LZMA, and LZMA2 stream bindings.
        *   `schema.go`: Declarative schema registries for v1.x (1000), v2.x (2000), v3.x (3000), v4.x (4000), v5.x (5000), and v6.x (6000) records.
        *   `records.go`: Sequential record deserializer with UTF-16LE decoding.
        *   `decrypt.go`: Cryptographic key derivation and RC4 (v5) / XChaCha20 (v6) stream decryption layers.
        *   `optimizer.go`: CALL/JMP absolute target address restoration filters.
        *   `extract.go`: Multi-slice payload extractors and checksum verifiers.
        *   `orchestrator.go`: High-level list and extract loops.
        *   `crack.go`: Concurrent, multi-threaded password recovery and brute-force engine.
        *   **`ifps/`** - Native Inno Free Pascal Script (IFPS) parser:
            *   `types.go`: OpCode and TypeCode constant tables.
            *   `parser.go`: Binary deserializer of `CompiledCode.bin` structures.
            *   `disasm.go`: Linear sweep bytecode disassembler and assembly formatter.
    *   **`main.go`** - Command-line interface entry point.
    *   **`cgo_exports.go`** - CGo shared library exported entry points.
    *   **`innounpack.py`** - Standard ctypes Python wrapper with recovery defaults.
    *   **`test_innounpack.py`** - Python unit-test suite.

---

## 2. Compilation Guide

Go provides two different build paths: a **pure Go CLI binary** (which can be compiled with zero external dependencies for any target on earth) and a **C-shared library** (which requires a host C compiler and is used by Python ctypes).

### 2.1 Compiling the CLI Binary (Pure Go)
Because the CLI binary has zero C dependencies, **you can cross-compile it for any operating system and architecture directly from your current machine**.

Change directory into `innounp-go/` and run the appropriate command:

#### Compilation for macOS (Apple Silicon - M1/M2/M3/M4/M5/...)
```bash
GOOS=darwin GOARCH=arm64 go build -o innounp-go main.go cgo_exports.go
```

#### Compilation for macOS (Intel)
```bash
GOOS=darwin GOARCH=amd64 go build -o innounp-go main.go cgo_exports.go
```

#### Compilation for Linux (x64)
```bash
GOOS=linux GOARCH=amd64 go build -o innounp-go main.go cgo_exports.go
```

#### Compilation for Windows (x64)
```bash
GOOS=windows GOARCH=amd64 go build -o innounp-go.exe main.go cgo_exports.go
```

---

### 2.2 Compiling the Shared Library (For Python ctypes API)
Building shared libraries requires CGo, which depends on a platform-native C compiler. Ensure you have the prerequisites installed:
*   **macOS:** Install Xcode Command Line Tools (`xcode-select --install`).
*   **Linux:** Install standard build tools (`sudo apt install build-essential` or `sudo dnf groupinstall "Development Tools"`).
*   **Windows:** Install MinGW-w64 (via MSYS2, Chocolatey, or w64devkit).

Inside the `innounp-go/` directory, execute the native build command:

#### Compilation on macOS (creates `libinnounpack.dylib`)
```bash
go build -buildmode=c-shared -o libinnounpack.dylib
```

#### Compilation on Linux (creates `libinnounpack.so`)
```bash
go build -buildmode=c-shared -o libinnounpack.so
```

#### Compilation on Windows (creates `libinnounpack.dll`)
```bash
go build -buildmode=c-shared -o libinnounpack.dll
```

---

## 3. Usage Instructions

### 3.1 Command-Line Interface (CLI)
Running the compiled native CLI binary against any Inno Setup installer executable verifies its internal offset tables, performs magic boundary checking, detects the installer version, and displays its block metadata:

```bash
./innounp-go [flags] <path_to_installer_exe_or_bytecode>
```

#### Supported CLI Flags:
*   `-l` - List-Only Mode: Prints out a beautifully aligned table containing IDs, uncompressed file sizes, compression status, password protection, and target destination directories.
*   `-o <directory_path>` - Output extraction folder. Automatically creates the directory (with `0755` permissions) if it does not exist on disk.
*   `-p <password>` - Explicit decryption password.
*   `-crack` - Initiates a multi-core, parallel dictionary attack using our built-in forensic dictionary of standard malware and installation passwords. **If found, the password is automatically injected to list or extract the files in-place!**
*   `-w <path_to_wordlist>` - Initiates a concurrent parallel dictionary attack using passwords read line-by-line from a specified wordlist (e.g. `rockyou.txt`). **If found, the password is automatically injected to complete the run.**
*   `-d` - Native Decompiler Mode: Extracts and disassembles compiled Pascal Script bytecode (`CompiledCode.bin`) in-memory. **Auto-detects format:** accepts both a full setup executable or a raw standalone `.bin` file as the path!

#### Example Output (Password Recovery + Auto-Extraction):
```text
Analyzing Inno Setup Executable: my_installer.exe
================================================================================
Loader Offset Table verified successfully!
...
================================================================================
Detected Inno Setup Installer Version: 5500 (Format: Unicode)
Number of File Payloads:               4
================================================================================
Initiating Multi-Core Parallel Password Recovery...
Using built-in quick dictionary of 25 forensic keys

[+] PASSWORD RECOVERED SUCCESSFULLY!
    Password:  infected
    Hash Type: SHA-1
    Guesses:   25

================================================================================
Extracting payloads to: extracted_my_installer
--------------------------------------------------------------------------------
Decrypting & Extracting   bin/malware.exe                          ... OK
Decrypting & Extracting   bin/config.json                          ... OK
================================================================================
EXTRACTION COMPLETED SUMMARY:
--------------------------------------------------------------------------------
Total Files Processed:     4
Successfully Extracted:    4
Failed to Extract:         0
Total Bytes Decompressed:  819200 bytes
Destination Directory:     extracted_my_installer
Used Password:             infected
================================================================================
```

---

### 3.2 Python API Bindings
The Python module `innounpack.py` loads the compiled shared library and provides clean, thread-safe, high-performance APIs.

#### Listing Files (Metadata Inspection)
```python
import innounpack

installer_path = "my_installer.exe"

try:
    files = innounpack.list_files(installer_path)

    print(f"Discovered {len(files)} files:")
    for f in files:
         print(f"ID: {f['id']} | File: {f['dest_name']} | Size: {f['original_size']} bytes | Encrypted: {f['encrypted']}")
except Exception as e:
    print(f"Error inspecting installer: {e}")
```

#### Parallel Password Cracking (In-Process Forensic Scanner)
`crack_password` spawns multi-core parallel routines in-process to bruteforce/dictionary-attack the installer's protection keys:

```python
import innounpack

installer_path = "protected_installer.exe"

# 1. Run dictionary attack (omit wordlist parameter to use the built-in forensic list)
result = innounpack.crack_password(installer_path, wordlist=["admin", "password", "infected"])

if result and result["PasswordFound"]:
    print(f"[+] Decryption password found: {result['Password']} (Hash Type: {result['HashType']})")

    # 2. Automatically extract files in-process using the recovered key!
    innounpack.extract_all(installer_path, "./extracted_payloads", password=result["Password"])
else:
    print("[-] Password was not recovered.")
```

#### Native Bytecode Decompilation (In-Process Disassembler)
`decompile_script` reads and disassembles compiled Pascal Script bytecode. It features an incredibly versatile API, supporting **both** string file paths and raw binary buffers directly in-memory!

```python
import innounpack

# Example A: Decompile from a full installer exe on disk (in-memory extraction & disasm)
assembly_from_exe = innounpack.decompile_script("my_installer.exe")
print(assembly_from_exe)

# Example B: Decompile from a raw, standalone bytecode buffer directly (No disk I/O!)
# This is perfect for advanced pipelines (like CAPE Sandbox) that load blobs from DBs/streams
raw_bytecode_bytes = b"IFPS\x17\x00..."  # binary CompiledCode payload
assembly_from_memory = innounpack.decompile_script(raw_bytecode_bytes)
print(assembly_from_memory)
```

#### Extracting Payloads (Explicit Decryption)
```python
import innounpack

success = innounpack.extract_all("installer.exe", "./output", password="ExplicitPassword")
```

---

## 4. Under the Hood: Technical Achievements

### 4.1 Schema-Driven Record Parser
Delphi structures are notoriously packed and compiler-dependent. Instead of generating hundreds of individual record mappings, `InnoUnp-Go` uses a **declarative, dynamic schema registry** (`parser/schema.go`). Record layouts (WideStrings, AnsiStrings, bitsets, enums, and scalar integers) are described in schemas. The parser reads streams sequentially based on these descriptors.

This enables native, error-free support for nearly **30 years of Inno Setup compilers**—including changing field sizes (like v3's 4-byte file sizes vs v4/v5/v6's 8-byte file sizes)—without writing separate parsing layers.

### 4.2 Stream Decryption Wrapper
When password protection is enabled, encryption is applied over the compressed payload. To decompress, `InnoUnp-Go` feeds raw segments into `CRCChunkReader` (which validates chunk boundaries), wraps it inside `DecryptReader` (which runs in-place RC4 or XChaCha20 decryption), and passes the decrypted stream directly to standard decompressors. This ensures **zero-copy streaming performance**.

### 4.3 CALL/JMP Target Address Restoration
Inno Setup pre-filters executables (`.exe`, `.dll`) by converting relative `CALL` and `JMP` targets to absolute offsets, boosting the compression ratio. `InnoUnp-Go` implements byte-accurate reverse transformations (`TransformCallInstructions` for legacy and `TransformCallInstructions5309` for modern installers), restoring files to their exact original SHA-256 byte-exact states.

### 4.4 C Boundary Memory Safety
Memory allocated on the Go heap or C heap must be managed carefully. To prevent memory leaks during Python execution, Go's `ListInnoFiles` exports the JSON-serialized file list on the C heap, and `innounpack.py` wraps calls in `try...finally` statements that automatically invoke Go's exported `FreeString` deallocator on the C pointer, guaranteeing **leak-free in-process parsing**.

---

## 5. Acknowledgements & Special Thanks

This project is built upon decades of outstanding reverse-engineering and open-source contributions from the community. We express our deepest gratitude and special thanks to:

1.  **Josef Rathlev** (and the contributors of **`innounp`**): For creating the legendary, battle-tested Object Pascal-based Inno Setup Unpacker command-line tool, which served as the foundational layout blueprint and structural reference for this Go implementation.
2.  **Daniel Scharrer** (author of **`innoextract`**): For his incredible work engineering a clean, cross-platform C++ Inno Setup extractor, which provided invaluable reference structures, and **gdesmar** for his fork focusing on Pascal Script bytecode (`CompiledCode.bin`) string-extraction concepts.
3.  **Gemini**, and **doomedraven**: For collaborating hand-in-hand to design, port, implement, and fully verify this modern, schema-driven Go porting initiative from legacy Object Pascal to modern Go, achieving a new milestone in cross-platform forensic utility tooling.
