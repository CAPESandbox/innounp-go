package ifps

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ReadString deserializes a standard Pascal-style string: [4-byte length] [string bytes].
func readString(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}

	if length == 0 {
		return "", nil
	}

	// Safety cap to prevent out-of-memory on corrupted files
	if length > 1024*1024*10 { // 10MB string limit
		return "", errors.New("Pascal string length limit exceeded (corrupted header)")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

// readString8 reads a string prefixed by a 1-byte length count (used for external function names).
func readString8(r io.Reader) (string, error) {
	var length uint8
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}

	if length == 0 {
		return "", nil
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

// readPrefixedBytes reads a 4-byte length-prefixed raw bytes block as a sub-stream buffer.
func readPrefixedBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	if length == 0 {
		return nil, nil
	}

	if length > 1024*1024*10 { // 10MB limit
		return nil, errors.New("prefixed bytes block length limit exceeded")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// ParseType parses a Type block from CompiledCode.bin.
func parseType(r io.Reader, index uint32, version uint32, types []IFPSType) (IFPSType, error) {
	var bTypeVal uint8
	if err := binary.Read(r, binary.LittleEndian, &bTypeVal); err != nil {
		return IFPSType{}, fmt.Errorf("failed to read type base code byte: %w", err)
	}

	// High bit indicates if the type is exported
	exported := (bTypeVal & 0x80) != 0
	baseType := TypeCode(bTypeVal & 0x7F)

	tbl := IFPSType{Index: index, BaseType: baseType}

	switch baseType {
	case TC_Class, TC_ExtClass:
		name, err := readString(r)
		if err != nil {
			return IFPSType{}, fmt.Errorf("failed to read class name: %w", err)
		}
		_ = name // class name discarded or handled dynamically

	case TC_ProcPtr:
		// ProcPtr specifications are read as length-prefixed binary metadata
		specLen, err := readString(r)
		if err != nil {
			return IFPSType{}, fmt.Errorf("failed to read ProcPtr specification string: %w", err)
		}
		_ = specLen

	case TC_Interface:
		// Read 16-byte UUID / GUID
		guid := make([]byte, 16)
		if _, err := io.ReadFull(r, guid); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read interface GUID: %w", err)
		}

	case TC_Set:
		var size uint32
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read set bit-size: %w", err)
		}

	case TC_StaticArray:
		var elemType uint32
		if err := binary.Read(r, binary.LittleEndian, &elemType); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read static array element type: %w", err)
		}
		var size uint32
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read static array size: %w", err)
		}
		tbl.ElementType = elemType
		tbl.StaticSize = size

		if version > 22 {
			var offset uint32
			if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
				return IFPSType{}, fmt.Errorf("failed to read static array offset: %w", err)
			}
		}

	case TC_Array:
		var elemType uint32
		if err := binary.Read(r, binary.LittleEndian, &elemType); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read array element type: %w", err)
		}
		tbl.ElementType = elemType

	case TC_Record:
		var count uint32
		if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read record field count: %w", err)
		}

		if count > 10000 {
			return IFPSType{}, errors.New("excessive record fields count in type definition")
		}

		tbl.Fields = make([]IFPSTypeRecordField, count)
		for i := uint32(0); i < count; i++ {
			var mType uint32
			if err := binary.Read(r, binary.LittleEndian, &mType); err != nil {
				return IFPSType{}, fmt.Errorf("failed to read record field %d type: %w", i, err)
			}
			tbl.Fields[i] = IFPSTypeRecordField{Type: mType, Name: fmt.Sprintf("Field%d", i)}
		}
	}

	if exported {
		symbol, err := readString(r)
		if err != nil {
			return IFPSType{}, fmt.Errorf("failed to read type exported symbol: %w", err)
		}
		_ = symbol

		if version <= 21 {
			name, err := readString(r)
			if err != nil {
				return IFPSType{}, fmt.Errorf("failed to read type exported name: %w", err)
			}
			_ = name
		}
	}

	if version >= 21 {
		if err := skipAttributes(r, types); err != nil {
			return IFPSType{}, fmt.Errorf("failed to skip type attributes: %w", err)
		}
	}

	return tbl, nil
}

// readCString reads a standard null-terminated C-string from the stream.
func readCString(r io.Reader) (string, error) {
	var buf bytes.Buffer
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			return "", err
		}
		if b[0] == 0 {
			break
		}
		buf.WriteByte(b[0])
	}
	return buf.String(), nil
}

// parseDeclSpecF deserializes function parameters calling spec from external DLL signature blocks.
func parseDeclSpecF(r *bytes.Reader, version uint32) (*IFPSProcSignature, error) {
	curr, _ := r.Seek(0, io.SeekCurrent)

	// Peek first 10 bytes to branch signature formats
	peekBuf := make([]byte, 10)
	nRead, _ := r.Read(peekBuf)
	r.Seek(curr, io.SeekStart)

	if nRead >= 4 && string(peekBuf[:4]) == "dll:" {
		// DLL Import!
		r.Seek(4, io.SeekCurrent) // consume "dll:"

		// Check if next bytes are "files:"
		filesBuf := make([]byte, 6)
		r.Read(filesBuf)
		if string(filesBuf) != "files:" {
			r.Seek(-6, io.SeekCurrent) // seek back files:
		}

		// Read module dll name (e.g. "kernel32.dll")
		symbol, err := readCString(r)
		if err != nil {
			return nil, err
		}

		// Read imported function name (e.g. "CreateFileA")
		importName, err := readCString(r)
		if err != nil {
			return nil, err
		}
		_ = symbol
		_ = importName

		// Read calling convention (1 byte)
		var conv uint8
		binary.Read(r, binary.LittleEndian, &conv)

		// If version >= 23, read 2 load flag booleans (2 bytes)
		if version >= 23 {
			var delay, alter uint8
			binary.Read(r, binary.LittleEndian, &delay)
			binary.Read(r, binary.LittleEndian, &alter)
		}

		// Read procedure vs function specifier (1 byte)
		var isProc uint8
		binary.Read(r, binary.LittleEndian, &isProc)

		// Read parameter specs from the remaining bytes of this block
		var params []IFPSParam
		refBytes := make([]byte, 100)
		n, _ := r.Read(refBytes)
		for i := 0; i < n; i++ {
			params = append(params, IFPSParam{Type: 0, Mode: uint32(refBytes[i])})
		}

		return &IFPSProcSignature{
			Convention: CallingConvention(conv),
			Params:     params,
		}, nil

	} else if nRead >= 6 && string(peekBuf[:6]) == "class:" {
		// Class Member!
		r.Seek(6, io.SeekCurrent) // consume "class:"

		// If remaining bytes is 1, read 1 byte spec and pascal cc
		rem := r.Len()
		if rem == 1 {
			var spec uint8
			binary.Read(r, binary.LittleEndian, &spec)
			return &IFPSProcSignature{
				Convention: PascalCalling,
				Params:     []IFPSParam{{Type: 0, Mode: 0}},
			}, nil
		}

		// Otherwise, read class name and member name delimited by '|'
		readCString(r) // class name
		readCString(r) // member name

		var conv uint8
		binary.Read(r, binary.LittleEndian, &conv)

		// Read procedure vs function specifier
		var isProc uint8
		binary.Read(r, binary.LittleEndian, &isProc)

		var params []IFPSParam
		refBytes := make([]byte, 100)
		n, _ := r.Read(refBytes)
		for i := 0; i < n; i++ {
			params = append(params, IFPSParam{Type: 0, Mode: uint32(refBytes[i])})
		}

		return &IFPSProcSignature{
			Convention: CallingConvention(conv),
			Params:     params,
		}, nil

	} else if nRead >= 6 && string(peekBuf[:6]) == "intf:." {
		// Interface Method!
		r.Seek(6, io.SeekCurrent) // consume "intf:."

		var vtableIndex uint32
		binary.Read(r, binary.LittleEndian, &vtableIndex)

		var conv uint8
		binary.Read(r, binary.LittleEndian, &conv)

		var isProc uint8
		binary.Read(r, binary.LittleEndian, &isProc)

		var params []IFPSParam
		refBytes := make([]byte, 100)
		n, _ := r.Read(refBytes)
		for i := 0; i < n; i++ {
			params = append(params, IFPSParam{Type: 0, Mode: uint32(refBytes[i])})
		}

		return &IFPSProcSignature{
			Convention: CallingConvention(conv),
			Params:     params,
		}, nil

	} else {
		// Direct procedure/function with no prefix!
		var isProc uint8
		binary.Read(r, binary.LittleEndian, &isProc)

		var params []IFPSParam
		refBytes := make([]byte, 100)
		n, _ := r.Read(refBytes)
		for i := 0; i < n; i++ {
			params = append(params, IFPSParam{Type: 0, Mode: uint32(refBytes[i])})
		}

		return &IFPSProcSignature{
			Convention: RegisterCalling, // default
			Params:     params,
		}, nil
	}
}

// ParseFunction parses a Function block from CompiledCode.bin.
func parseFunction(r io.ReadSeeker, index uint32, version uint32, isUnicode bool, types []IFPSType) (IFPSFunction, error) {
	var tags uint8
	if err := binary.Read(r, binary.LittleEndian, &tags); err != nil {
		return IFPSFunction{}, fmt.Errorf("failed to read function tags: %w", err)
	}

	// Correct FTag IntFlag masks:
	// External = 0b0001 (0x01)
	// Exported = 0b0010 (0x02)
	// HasAttrs = 0b0100 (0x04)
	isExternal := (tags & 0x01) != 0
	exported := (tags & 0x02) != 0
	hasAttrs := (tags & 0x04) != 0

	fn := IFPSFunction{Index: index, IsExternal: isExternal}

	if isExternal {
		// External function names are always read with a 1-byte length prefix!
		var err error
		fn.Name, err = readString8(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read external function name: %w", err)
		}

		if exported {
			sigBytes, err := readPrefixedBytes(r)
			if err != nil {
				return IFPSFunction{}, fmt.Errorf("failed to read external signature block: %w", err)
			}
			// Parse calling conventions and parameter refs from signature sub-stream
			subR := bytes.NewReader(sigBytes)
			sig, err := parseDeclSpecF(subR, version)
			if err != nil {
				return IFPSFunction{}, fmt.Errorf("failed to parse DeclSpecF: %w", err)
			}
			fn.Signature = *sig
		}
	} else {
		var offset uint32
		if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function offset: %w", err)
		}
		var length uint32
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function length: %w", err)
		}

		if exported {
			var err error
			fn.Name, err = readString(r) // 4-byte length prefix!
			if err != nil {
				return IFPSFunction{}, fmt.Errorf("failed to read internal function name: %w", err)
			}
			// Discard internal decl specs block
			_, err = readPrefixedBytes(r)
			if err != nil {
				return IFPSFunction{}, fmt.Errorf("failed to read internal decl block: %w", err)
			}
		}

		// Seek detour to read bytecode bytes from the raw buffered block stream
		curr, _ := r.Seek(0, io.SeekCurrent)
		if _, err := r.Seek(int64(offset), io.SeekStart); err == nil {
			fn.Bytecode = make([]byte, length)
			r.Read(fn.Bytecode)
		}
		r.Seek(curr, io.SeekStart)
	}

	if hasAttrs {
		if err := skipAttributes(r, types); err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to skip function attributes: %w", err)
		}
	}

	return fn, nil
}

// ParseIFPS deserializes a raw CompiledCode.bin binary stream into an IFPSFile representation.
func ParseIFPS(r io.ReadSeeker, isUnicode bool) (*IFPSFile, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic header: %w", err)
	}

	if string(magic[:]) != "IFPS" {
		return nil, errors.New("invalid bytecode file: missing 'IFPS' magic header")
	}

	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("failed to read bytecode version: %w", err)
	}

	var countTypes uint32
	if err := binary.Read(r, binary.LittleEndian, &countTypes); err != nil {
		return nil, fmt.Errorf("failed to read type count: %w", err)
	}

	var countFunctions uint32
	if err := binary.Read(r, binary.LittleEndian, &countFunctions); err != nil {
		return nil, fmt.Errorf("failed to read function count: %w", err)
	}

	var countVariables uint32
	if err := binary.Read(r, binary.LittleEndian, &countVariables); err != nil {
		return nil, fmt.Errorf("failed to read variables count: %w", err)
	}

	var entryPoint uint32
	if err := binary.Read(r, binary.LittleEndian, &entryPoint); err != nil {
		return nil, fmt.Errorf("failed to read entry point offset: %w", err)
	}

	var importSize uint32
	if err := binary.Read(r, binary.LittleEndian, &importSize); err != nil {
		return nil, fmt.Errorf("failed to read import size: %w", err)
	}

	// Skip import block bytes if importSize is non-zero
	if importSize > 0 {
		if importSize > 1024*1024*10 { // 10MB limit
			return nil, errors.New("excessive import size in header")
		}
		discarded, err := io.CopyN(io.Discard, r, int64(importSize))
		if err != nil || discarded != int64(importSize) {
			return nil, fmt.Errorf("failed to skip import bytes of size %d: %w", importSize, err)
		}
	}

	// 1. Read Types Block
	types := make([]IFPSType, countTypes)
	for i := uint32(0); i < countTypes; i++ {
		t, err := parseType(r, i, version, types)
		if err != nil {
			return nil, fmt.Errorf("failed to parse type entry %d: %w", i, err)
		}
		types[i] = t
	}

	// 2. Read Functions Block
	funcs := make([]IFPSFunction, countFunctions)
	for i := uint32(0); i < countFunctions; i++ {
		f, err := parseFunction(r, i, version, isUnicode, types)
		if err != nil {
			return nil, fmt.Errorf("failed to parse function entry %d: %w", i, err)
		}
		funcs[i] = f
	}

	// 3. Read Variables Block
	globals := make([]IFPSVariable, countVariables)
	for i := uint32(0); i < countVariables; i++ {
		var varType uint32
		if err := binary.Read(r, binary.LittleEndian, &varType); err != nil {
			return nil, fmt.Errorf("failed to read global variable %d type: %w", i, err)
		}

		name, err := readString8(r) // Variable names always have a 1-byte length prefix!
		if err != nil {
			return nil, fmt.Errorf("failed to read global variable %d name: %w", i, err)
		}
		globals[i] = IFPSVariable{Index: i, Type: varType, Name: name}
	}

	return &IFPSFile{
		Magic:     magic,
		Version:   version,
		EntryPoint: entryPoint,
		Types:     types,
		Globals:   globals,
		Functions: funcs,
	}, nil
}

// skipAttributes reads and discards attributes stubs sequentially written in versions >= 21.
func skipAttributes(r io.Reader, types []IFPSType) error {
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return err
	}
	for i := uint32(0); i < count; i++ {
		name, err := readString(r)
		if err != nil {
			return err
		}
		_ = name

		var valCount uint32
		if err := binary.Read(r, binary.LittleEndian, &valCount); err != nil {
			return err
		}
		for j := uint32(0); j < valCount; j++ {
			var valType uint32
			if err := binary.Read(r, binary.LittleEndian, &valType); err != nil {
				return err
			}
			if int(valType) >= len(types) {
				return fmt.Errorf("attribute type index %d out of bounds (types count %d)", valType, len(types))
			}
			t := types[valType]
			// Skip actual value bytes based on the TypeCode width or string length
			if err := skipAttributeValue(r, t); err != nil {
				return err
			}
		}
	}
	return nil
}

// skipAttributeValue discards raw serialized bytes of a given value type index.
func skipAttributeValue(r io.Reader, t IFPSType) error {
	switch t.BaseType {
	case TC_U08, TC_S08, TC_Char:
		return skipNBytes(r, 1)
	case TC_U16, TC_S16, TC_WideChar:
		return skipNBytes(r, 2)
	case TC_U32, TC_S32, TC_Single, TC_Class, TC_ExtClass, TC_Interface:
		return skipNBytes(r, 4)
	case TC_Double, TC_S64, TC_Currency:
		return skipNBytes(r, 8)
	case TC_Extended:
		return skipNBytes(r, 10)
	case TC_AnsiString, TC_WideString, TC_UnicodeString, TC_PChar:
		s, err := readString(r)
		if err != nil {
			return err
		}
		_ = s
	case TC_ProcPtr:
		return skipNBytes(r, 4) // reads 32-bit function ID index
	case TC_Set:
		// TC_Set has variable width stored as bit count (size in bytes = (bits + 7) / 8)
		// We read the set bits property value directly or assume static fallback if not stored
		return skipNBytes(r, 4) // sets are usually passed as 4-byte indexes
	}
	return nil
}

func skipNBytes(r io.Reader, n int64) error {
	_, err := io.CopyN(io.Discard, r, n)
	return err
}

func getPC(r io.Reader) int64 {
	if s, ok := r.(io.Seeker); ok {
		pos, _ := s.Seek(0, io.SeekCurrent)
		return pos
	}
	return -1
}
