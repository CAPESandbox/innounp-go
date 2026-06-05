package ifps

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseIFPS_EmptyHeaders(t *testing.T) {
	// Construct mock header for 0 types, 0 functions, 0 variables
	buf := new(bytes.Buffer)
	buf.Write([]byte("IFPS"))                         // Magic
	binary.Write(buf, binary.LittleEndian, uint32(23)) // Version
	binary.Write(buf, binary.LittleEndian, uint32(0))  // CountTypes
	binary.Write(buf, binary.LittleEndian, uint32(0))  // CountFunctions
	binary.Write(buf, binary.LittleEndian, uint32(0))  // CountVariables
	binary.Write(buf, binary.LittleEndian, uint32(100)) // EntryPoint
	binary.Write(buf, binary.LittleEndian, uint32(0))  // ImportSize

	file, err := ParseIFPS(bytes.NewReader(buf.Bytes()), false)
	if err != nil {
		t.Fatalf("expected successful ParseIFPS, got error: %v", err)
	}

	if string(file.Magic[:]) != "IFPS" {
		t.Errorf("expected magic 'IFPS', got %q", string(file.Magic[:]))
	}
	if file.Version != 23 {
		t.Errorf("expected version 23, got %d", file.Version)
	}
	if file.EntryPoint != 100 {
		t.Errorf("expected entry point 100, got %d", file.EntryPoint)
	}
	if len(file.Types) != 0 {
		t.Errorf("expected 0 types, got %d", len(file.Types))
	}
}

func TestParseIFPS_InvalidMagic(t *testing.T) {
	buf := bytes.NewReader([]byte("MZ\x90\x00\x03\x00\x00\x00"))
	_, err := ParseIFPS(buf, false)
	if err == nil {
		t.Error("expected ParseIFPS to fail due to invalid magic, but got success")
	}
}

func TestDisassemble_FormatValidation(t *testing.T) {
	// Construct a mock parsed IFPS file structure manually
	mockFile := &IFPSFile{
		Magic:      [4]byte{'I', 'F', 'P', 'S'},
		Version:    21,
		EntryPoint: 0x200,
		Types: []IFPSType{
			{Index: 0, BaseType: TC_S32}, // S32 Integer
			{Index: 1, BaseType: TC_AnsiString},
		},
		Globals: []IFPSVariable{
			{Index: 0, Type: 1, Name: "MyPass"},
		},
		Functions: []IFPSFunction{
			{
				Index:      0,
				IsExternal: true,
				Name:       "RegQueryStringValue",
				ImportName: "advapi32.dll",
				Signature: IFPSProcSignature{
					Convention: StdcallCalling,
					ReturnType: 0,
					Params:     []IFPSParam{{Type: 0, Mode: 0}},
				},
			},
			{
				Index:      1,
				IsExternal: false,
				Name:       "InitializeSetup",
				Signature: IFPSProcSignature{
					Convention: PascalCalling,
					ReturnType: 0,
				},
				Bytecode: []byte{
					byte(OpPush), 0x00, 0x00, 0x00, 0x00, // PUSH Index 0
					byte(OpCall), 0x00, 0x00, 0x00, 0x00, // CALL Func 0
					byte(OpRet),                          // RET
				},
			},
		},
	}

	disasm, err := Disassemble(mockFile)
	if err != nil {
		t.Fatalf("disassembly failed: %v", err)
	}

	// Verify that key sections are printed and mapped correctly
	if !strings.Contains(disasm, "PASCAL SCRIPT BYTECODE DISASSEMBLY (IFPS)") {
		t.Error("missing disassembly title header")
	}
	if !strings.Contains(disasm, "Type 0") || !strings.Contains(disasm, "S32 (Integer)") {
		t.Error("failed to map S32 Type Code to name")
	}
	if !strings.Contains(disasm, "Var 0") || !strings.Contains(disasm, "MyPass") {
		t.Error("failed to format global variables")
	}
	if !strings.Contains(disasm, "RegQueryStringValue") || !strings.Contains(disasm, "advapi32.dll") {
		t.Error("failed to format external imported module DLL names and signatures")
	}
	if !strings.Contains(disasm, "PUSH") || !strings.Contains(disasm, "Index: 0") {
		t.Error("failed to disassemble PUSH instruction")
	}
	if !strings.Contains(disasm, "RET") {
		t.Error("failed to disassemble RET instruction")
	}
}
