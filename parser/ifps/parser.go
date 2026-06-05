package ifps

import (
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

// ParseSignature parses a calling convention, return type, and parameters spec.
func parseSignature(r io.Reader) (*IFPSProcSignature, error) {
	var convVal uint32
	if err := binary.Read(r, binary.LittleEndian, &convVal); err != nil {
		return nil, fmt.Errorf("failed to read signature convention: %w", err)
	}

	var retType uint32
	if err := binary.Read(r, binary.LittleEndian, &retType); err != nil {
		return nil, fmt.Errorf("failed to read signature return type: %w", err)
	}

	var paramCount uint32
	if err := binary.Read(r, binary.LittleEndian, &paramCount); err != nil {
		return nil, fmt.Errorf("failed to read signature param count: %w", err)
	}

	// Cap param count for security
	if paramCount > 1000 {
		return nil, errors.New("excessive parameter count in function signature")
	}

	params := make([]IFPSParam, paramCount)
	for i := uint32(0); i < paramCount; i++ {
		var pType uint32
		if err := binary.Read(r, binary.LittleEndian, &pType); err != nil {
			return nil, fmt.Errorf("failed to read param %d type: %w", i, err)
		}
		var pMode uint32
		if err := binary.Read(r, binary.LittleEndian, &pMode); err != nil {
			return nil, fmt.Errorf("failed to read param %d mode: %w", i, err)
		}
		params[i] = IFPSParam{Type: pType, Mode: pMode}
	}

	return &IFPSProcSignature{
		Convention: CallingConvention(convVal),
		ReturnType: retType,
		Params:     params,
	}, nil
}

// ParseType parses a Type block.
func parseType(r io.Reader, index uint32) (IFPSType, error) {
	var baseTypeVal uint32
	if err := binary.Read(r, binary.LittleEndian, &baseTypeVal); err != nil {
		return IFPSType{}, fmt.Errorf("failed to read type base code: %w", err)
	}
	baseType := TypeCode(baseTypeVal)

	tbl := IFPSType{Index: index, BaseType: baseType}

	switch baseType {
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
			name, err := readString(r)
			if err != nil {
				return IFPSType{}, fmt.Errorf("failed to read record field %d name: %w", i, err)
			}
			tbl.Fields[i] = IFPSTypeRecordField{Name: name, Type: mType}
		}

	case TC_Array:
		if err := binary.Read(r, binary.LittleEndian, &tbl.ElementType); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read array element type: %w", err)
		}

	case TC_StaticArray:
		if err := binary.Read(r, binary.LittleEndian, &tbl.ElementType); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read static array element type: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &tbl.StaticSize); err != nil {
			return IFPSType{}, fmt.Errorf("failed to read static array size: %w", err)
		}

	case TC_ProcPtr:
		sig, err := parseSignature(r)
		if err != nil {
			return IFPSType{}, fmt.Errorf("failed to read ProcPtr signature: %w", err)
		}
		tbl.Signature = sig
	}

	return tbl, nil
}

// ParseFunction parses a Function block.
func parseFunction(r io.Reader, index uint32) (IFPSFunction, error) {
	var isExternalVal uint32
	if err := binary.Read(r, binary.LittleEndian, &isExternalVal); err != nil {
		return IFPSFunction{}, fmt.Errorf("failed to read function type: %w", err)
	}
	isExternal := isExternalVal != 0

	fn := IFPSFunction{Index: index, IsExternal: isExternal}

	var err error
	if isExternal {
		fn.Name, err = readString(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read external function name: %w", err)
		}
		fn.ImportName, err = readString(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read external function import name: %w", err)
		}
		sig, err := parseSignature(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read external function signature: %w", err)
		}
		fn.Signature = *sig
	} else {
		fn.Name, err = readString(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function name: %w", err)
		}
		sig, err := parseSignature(r)
		if err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function signature: %w", err)
		}
		fn.Signature = *sig

		var bytecodeSize uint32
		if err := binary.Read(r, binary.LittleEndian, &bytecodeSize); err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function bytecode size: %w", err)
		}

		if bytecodeSize > 1024*1024*50 { // 50MB bytecode limit
			return IFPSFunction{}, errors.New("internal function bytecode size exceeds safety limit")
		}

		fn.Bytecode = make([]byte, bytecodeSize)
		if _, err := io.ReadFull(r, fn.Bytecode); err != nil {
			return IFPSFunction{}, fmt.Errorf("failed to read internal function bytecode: %w", err)
		}
	}

	return fn, nil
}

// ParseIFPS deserializes a raw CompiledCode.bin binary stream into an IFPSFile representation.
func ParseIFPS(r io.Reader) (*IFPSFile, error) {
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
		t, err := parseType(r, i)
		if err != nil {
			return nil, fmt.Errorf("failed to parse type entry %d: %w", i, err)
		}
		types[i] = t
	}

	// 2. Read Functions Block
	funcs := make([]IFPSFunction, countFunctions)
	for i := uint32(0); i < countFunctions; i++ {
		f, err := parseFunction(r, i)
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
		name, err := readString(r)
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
