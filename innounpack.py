import ctypes
import json
import os
import sys

# Standard forensic analysis and installer password defaults
DEFAULT_COMMON_PASSWORDS = [
    "password", "123456", "12345", "1234", "admin", "setup", "install",
    "secret", "private", "pass", "123", "Inno", "InnoSetup", "setup123",
    "malware", "infected", "cracked", "crack", "key", "license",
    "infected123", "password123", "admin123", "setup.exe", "12345678",
]

# Determine library path and extension based on the operating system
def _load_library():
    if sys.platform == 'darwin':
        lib_name = "libinnounpack.dylib"
    elif sys.platform == 'win32':
        lib_name = "libinnounpack.dll"
    else:
        lib_name = "libinnounpack.so"

    # Search in the current file's directory
    dir_path = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(dir_path, lib_name)

    if not os.path.exists(full_path):
        # Fall back to cwd
        full_path = os.path.abspath(lib_name)

    if not os.path.exists(full_path):
        raise FileNotFoundError(
            f"Could not locate C-shared library: {lib_name}. "
            f"Please run 'go build -buildmode=c-shared -o {lib_name}' first."
        )

    return ctypes.CDLL(full_path)

# Initialize global shared library instance
try:
    _lib = _load_library()
    
    # Define argument and return types for ctypes mapping
    _lib.ExtractInno.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    _lib.ExtractInno.restype = ctypes.c_int

    _lib.ListInnoFiles.argtypes = [ctypes.c_char_p]
    _lib.ListInnoFiles.restype = ctypes.c_char_p  # Returns raw C-string pointer

    _lib.CrackInnoPassword.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    _lib.CrackInnoPassword.restype = ctypes.c_char_p

    _lib.DecompileInnoScript.argtypes = [ctypes.c_char_p]
    _lib.DecompileInnoScript.restype = ctypes.c_char_p

    _lib.DecompileStandaloneScript.argtypes = [ctypes.c_char_p]
    _lib.DecompileStandaloneScript.restype = ctypes.c_char_p

    _lib.DecompileStandaloneBytes.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _lib.DecompileStandaloneBytes.restype = ctypes.c_char_p

    _lib.FreeString.argtypes = [ctypes.c_char_p]
    _lib.FreeString.restype = None
except Exception as e:
    _lib = None
    # We allow loading of the module even if compilation hasn't occurred yet,
    # but actual calls will fail. This is standard Python modular design.

def list_files(installer_path: str) -> list:
    """
    Parses the Inno Setup installer executable and returns list of metadata
    for all embedded file payload entries.

    Returns:
        list of dict: [{"id": 0, "source_filename": "...", "dest_name": "...", "original_size": 1234, ...}]
    """
    if _lib is None:
        raise RuntimeError("Shared library is not loaded. Ensure C-shared compilation was successful.")

    if not os.path.exists(installer_path):
        raise FileNotFoundError(f"Installer executable not found: {installer_path}")

    # Encode path to standard null-terminated bytes for C-boundary
    path_bytes = installer_path.encode('utf-8')

    c_json_ptr = _lib.ListInnoFiles(path_bytes)
    if not c_json_ptr:
        raise Exception("Failed to list files: offset tables parsed successfully but block is corrupted or empty")

    try:
        # Cast C-string pointer to Python string and parse as JSON
        json_str = ctypes.c_char_p(c_json_ptr).value.decode('utf-8')
        return json.loads(json_str)
    finally:
        # Always free Go-allocated heap string back to avoid memory leak
        _lib.FreeString(c_json_ptr)

def extract_all(installer_path: str, output_directory: str, password: str = "") -> bool:
    """
    Decompresses and extracts all installer file payloads into the output directory.
    Supports password decryption if specified.

    Returns:
        bool: True if extraction was successful, False otherwise.
    """
    if _lib is None:
        raise RuntimeError("Shared library is not loaded.")

    if not os.path.exists(installer_path):
        raise FileNotFoundError(f"Installer executable not found: {installer_path}")

    res = _lib.ExtractInno(
        installer_path.encode('utf-8'),
        output_directory.encode('utf-8'),
        password.encode('utf-8')
    )
    return res == 0

def crack_password(installer_path: str, wordlist: list = None) -> dict:
    """
    Performs a high-performance concurrent parallel dictionary attack against the
    installer's password verification block.

    Args:
        installer_path (str): Path to the Inno Setup executable.
        wordlist (list of str): List of password guesses. If None, uses a default built-in
                                forensic list of 24 common analysis passwords.

    Returns:
        dict: {"PasswordFound": bool, "Password": str, "HashType": str, "TotalGuesses": int}
              Returns None if parsing failed or installer is not protected.
    """
    if _lib is None:
        raise RuntimeError("Shared library is not loaded.")

    if not os.path.exists(installer_path):
        raise FileNotFoundError(f"Installer executable not found: {installer_path}")

    if wordlist is None:
        wordlist = DEFAULT_COMMON_PASSWORDS

    # Encode inputs
    path_bytes = installer_path.encode('utf-8')
    wordlist_bytes = json.dumps(wordlist).encode('utf-8')

    c_json_ptr = _lib.CrackInnoPassword(path_bytes, wordlist_bytes)
    if not c_json_ptr:
        return None

    try:
        json_str = ctypes.c_char_p(c_json_ptr).value.decode('utf-8')
        return json.loads(json_str)
    finally:
        _lib.FreeString(c_json_ptr)

def decompile_script(file_or_bytes) -> str:
    """
    Decompiles compiled Pascal script bytecode and returns human-readable formatted assembly text.
    Supports:
    - String file path (full setup EXE or standalone CompiledCode.bin file)
    - Raw bytes/bytearray buffer of CompiledCode.bin directly in-memory!

    Args:
        file_or_bytes (str or bytes): Path to the file, or raw bytes bytecode buffer.

    Returns:
        str: Disassembly formatted text.
    """
    if _lib is None:
        raise RuntimeError("Shared library is not loaded.")

    # 1. Handle in-memory bytes/bytearray decompilation directly!
    if isinstance(file_or_bytes, (bytes, bytearray)):
        c_str_ptr = _lib.DecompileStandaloneBytes(file_or_bytes, len(file_or_bytes))
        if not c_str_ptr:
            raise Exception("Decompilation failed: invalid or corrupted bytecode payload buffer")
        try:
            return ctypes.c_char_p(c_str_ptr).value.decode('utf-8')
        finally:
            _lib.FreeString(c_str_ptr)

    # 2. Handle string file path decompilation
    file_path = file_or_bytes
    if not isinstance(file_path, str):
        raise TypeError("Input must be a file path string or raw bytes/bytearray buffer")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    # Detect standalone "IFPS" bytecode file vs setup PE executable
    is_standalone = False
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            is_standalone = (magic == b"IFPS")
    except Exception:
        pass

    path_bytes = file_path.encode('utf-8')

    if is_standalone:
        c_str_ptr = _lib.DecompileStandaloneScript(path_bytes)
    else:
        c_str_ptr = _lib.DecompileInnoScript(path_bytes)

    if not c_str_ptr:
        raise Exception("Decompilation failed: file is not a valid CompiledCode payload or does not contain scripting logic")

    try:
        return ctypes.c_char_p(c_str_ptr).value.decode('utf-8')
    finally:
        _lib.FreeString(c_str_ptr)
