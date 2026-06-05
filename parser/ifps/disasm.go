package ifps

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Disassemble compiles the parsed IFPSFile structures into a beautiful, human-readable text.
func Disassemble(file *IFPSFile) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("================================================================================\n")
	buf.WriteString("PASCAL SCRIPT BYTECODE DISASSEMBLY (IFPS)\n")
	buf.WriteString("================================================================================\n")
	fmt.Fprintf(&buf, "Bytecode Version:     %d\n", file.Version)
	fmt.Fprintf(&buf, "Global Entry Point:   0x%X\n", file.EntryPoint)
	fmt.Fprintf(&buf, "Total Types:          %d\n", len(file.Types))
	fmt.Fprintf(&buf, "Total Global Vars:    %d\n", len(file.Globals))
	fmt.Fprintf(&buf, "Total Functions:      %d\n", len(file.Functions))
	buf.WriteString("================================================================================\n\n")

	// 1. Types Registry Table
	buf.WriteString("[Types Table]\n")
	buf.WriteString("--------------------------------------------------------------------------------\n")
	for _, t := range file.Types {
		fmt.Fprintf(&buf, "  Type %-2d: Base: %-12s ", t.Index, mapTypeCodeName(t.BaseType))
		switch t.BaseType {
		case TC_Record:
			buf.WriteString("record { ")
			for i, f := range t.Fields {
				if i > 0 {
					buf.WriteString(", ")
				}
				fmt.Fprintf(&buf, "%s: Type %d", f.Name, f.Type)
			}
			buf.WriteString(" }")
		case TC_Array:
			fmt.Fprintf(&buf, "array of Type %d", t.ElementType)
		case TC_StaticArray:
			fmt.Fprintf(&buf, "array[0..%d] of Type %d", t.StaticSize-1, t.ElementType)
		case TC_ProcPtr:
			if t.Signature != nil {
				fmt.Fprintf(&buf, "procedure (returns Type %d, Calling: %s)", t.Signature.ReturnType, mapConventionName(t.Signature.Convention))
			}
		}
		buf.WriteString("\n")
	}
	buf.WriteString("================================================================================\n\n")

	// 2. Global Variables Table
	buf.WriteString("[Global Variables Table]\n")
	buf.WriteString("--------------------------------------------------------------------------------\n")
	for _, v := range file.Globals {
		fmt.Fprintf(&buf, "  Var %-2d:  Type %-2d | Name: %s\n", v.Index, v.Type, v.Name)
	}
	buf.WriteString("================================================================================\n\n")

	// 3. Imported DLL/API Functions (Highest Forensic Signal!)
	buf.WriteString("[Imported API DLL Functions]\n")
	buf.WriteString("--------------------------------------------------------------------------------\n")
	hasImports := false
	for _, f := range file.Functions {
		if f.IsExternal {
			hasImports = true
			fmt.Fprintf(&buf, "  Func %-2d: Module: %-16s | Name: %s (Calling: %s)\n", f.Index, f.ImportName, f.Name, mapConventionName(f.Signature.Convention))
			if len(f.Signature.Params) > 0 {
				buf.WriteString("           Params: ")
				for pi, param := range f.Signature.Params {
					if pi > 0 {
						buf.WriteString(", ")
					}
					fmt.Fprintf(&buf, "Type %d", param.Type)
				}
				buf.WriteString("\n")
			}
		}
	}
	if !hasImports {
		buf.WriteString("  (No external functions imported by the script)\n")
	}
	buf.WriteString("================================================================================\n\n")

	// 4. Internal Compiled Functions Disassembly
	buf.WriteString("[Internal Function Bytecode Sweeper]\n")
	buf.WriteString("--------------------------------------------------------------------------------\n")
	for _, f := range file.Functions {
		if !f.IsExternal {
			fmt.Fprintf(&buf, "  Function %s (Index: %d, Return Type: %d, Bytecode Size: %d bytes)\n", f.Name, f.Index, f.Signature.ReturnType, len(f.Bytecode))
			if len(f.Bytecode) > 0 {
				disassembleBytecode(&buf, f.Bytecode)
			}
			buf.WriteString("  ------------------------------------------------------------------------------\n")
		}
	}
	buf.WriteString("================================================================================\n")

	return buf.String(), nil
}

func disassembleBytecode(buf *bytes.Buffer, code []byte) {
	i := 0
	size := len(code)
	for i < size {
		op := Op(code[i])
		fmt.Fprintf(buf, "    0x%04X:  %-15s", i, mapOpName(op))

		// Linear sweep decoding step: advance program counter (PC)
		switch op {
		case OpAssign, OpCalculate, OpCompare, OpIn, OpIs:
			// These operators typically consume local variables/constants indices (e.g. 4-8 bytes)
			argSize := 8
			if i+1+argSize <= size {
				fmt.Fprintf(buf, " [Args: % X]", code[i+1:i+1+argSize])
				i += argSize
			}
		case OpPush, OpPop:
			argSize := 4
			if i+1+argSize <= size {
				fmt.Fprintf(buf, " [Index: %d]", binary.LittleEndian.Uint32(code[i+1:i+1+argSize]))
				i += argSize
			}
		case OpJump, OpJZ, OpJNZ:
			argSize := 4
			if i+1+argSize <= size {
				target := binary.LittleEndian.Uint32(code[i+1:i+1+argSize])
				fmt.Fprintf(buf, " -> Offset 0x%04X", target)
				i += argSize
			}
		case OpCall, OpCallVar:
			argSize := 4
			if i+1+argSize <= size {
				target := binary.LittleEndian.Uint32(code[i+1:i+1+argSize])
				fmt.Fprintf(buf, " Func ID: %d", target)
				i += argSize
			}
		}
		buf.WriteString("\n")
		i++
	}
}

func mapTypeCodeName(tc TypeCode) string {
	switch tc {
	case TC_U08:
		return "U08 (Byte)"
	case TC_S08:
		return "S08 (ShortInt)"
	case TC_U16:
		return "U16 (Word)"
	case TC_S16:
		return "S16 (SmallInt)"
	case TC_U32:
		return "U32 (LongWord)"
	case TC_S32:
		return "S32 (Integer)"
	case TC_S64:
		return "S64 (Int64)"
	case TC_Single:
		return "Single"
	case TC_Double:
		return "Double"
	case TC_Extended:
		return "Extended"
	case TC_Char:
		return "Char"
	case TC_WideChar:
		return "WideChar"
	case TC_AnsiString:
		return "AnsiString"
	case TC_UnicodeString:
		return "UnicodeString"
	case TC_Variant:
		return "Variant"
	case TC_Pointer:
		return "Pointer"
	case TC_Record:
		return "Record"
	case TC_Array:
		return "Array"
	case TC_StaticArray:
		return "StaticArray"
	case TC_Set:
		return "Set"
	case TC_Currency:
		return "Currency"
	case TC_Class:
		return "Class"
	case TC_Interface:
		return "Interface"
	case TC_ProcPtr:
		return "ProcedurePointer"
	default:
		return fmt.Sprintf("Unknown(0x%X)", uint32(tc))
	}
}

func mapConventionName(cv CallingConvention) string {
	switch cv {
	case CcRegister:
		return "register"
	case CcPascal:
		return "pascal"
	case CcCdecl:
		return "cdecl"
	case CcStdcall:
		return "stdcall"
	default:
		return "unknown"
	}
}

func mapOpName(op Op) string {
	switch op {
	case OpAssign:
		return "ASSIGN"
	case OpCalculate:
		return "CALCULATE"
	case OpPush:
		return "PUSH"
	case OpPop:
		return "POP"
	case OpCall:
		return "CALL"
	case OpCallVar:
		return "CALLVAR"
	case OpRet:
		return "RET"
	case OpJump:
		return "JUMP"
	case OpJZ:
		return "JZ (JumpIfZero)"
	case OpJNZ:
		return "JNZ (JumpIfNotZero)"
	case OpAnd:
		return "AND"
	case OpOr:
		return "OR"
	case OpNot:
		return "NOT"
	case OpMinus:
		return "MINUS"
	case OpCompare:
		return "COMPARE"
	case OpGetClassProperty:
		return "GETCLASSPROP"
	case OpSetClassProperty:
		return "SETCLASSPROP"
	case OpCreateEvent:
		return "CREATEEVENT"
	case OpSetEvent:
		return "SETEVENT"
	case OpGetEvent:
		return "GETEVENT"
	case OpIn:
		return "IN"
	case OpIs:
		return "IS"
	case OpAs:
		return "AS"
	case OpCalculateAssigned:
		return "CALC_ASSIGNED"
	case OpCalculateNotAssigned:
		return "CALC_NOT_ASSIGNED"
	case OpCalculateEqual:
		return "CALC_EQUAL"
	case OpCalculateNotEqual:
		return "CALC_NOT_EQUAL"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", byte(op))
	}
}
