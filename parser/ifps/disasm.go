package ifps

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Disassemble walks the types registry, variables, functions, and decodes bytecode instructions
// into clean, human-readable high-level symbolic assembly.
func Disassemble(f *IFPSFile) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("================================================================================\n")
	buf.WriteString("             INNO SETUP PASCAL SCRIPT BYTECODE DISASSEMBLY (IFPS)\n")
	buf.WriteString("================================================================================\n\n")

	// 1. Output Types Registry
	buf.WriteString("--- TYPES REGISTRY ---\n")
	for _, t := range f.Types {
		fmt.Fprintf(&buf, "Type %d: BaseType=%s\n", t.Index, mapTypeCodeName(t.BaseType))
		if t.BaseType == TC_Record {
			for idx, field := range t.Fields {
				fmt.Fprintf(&buf, "    Field [%d]: %s (Type Index %d)\n", idx, field.Name, field.Type)
			}
		} else if t.BaseType == TC_Array || t.BaseType == TC_StaticArray {
			fmt.Fprintf(&buf, "    ElementType: Type Index %d", t.ElementType)
			if t.BaseType == TC_StaticArray {
				fmt.Fprintf(&buf, ", StaticSize: %d", t.StaticSize)
			}
			buf.WriteString("\n")
		}
	}
	buf.WriteString("\n")

	// 2. Output Global Variables
	buf.WriteString("--- GLOBAL VARIABLES ---\n")
	for _, v := range f.Globals {
		fmt.Fprintf(&buf, "Var %d: %s (Type Index %d)\n", v.Index, v.Name, v.Type)
	}
	buf.WriteString("\n")

	// 3. Output Functions and Bytecode
	buf.WriteString("--- FUNCTIONS CATALOG ---\n")
	for _, fn := range f.Functions {
		if fn.IsExternal {
			fmt.Fprintf(&buf, "\nExternal Function [%d]: %s (Import: %s)\n", fn.Index, fn.Name, fn.ImportName)
			fmt.Fprintf(&buf, "    Signature: CallingConv=%s, ReturnType Index=%d, ParamsCount=%d\n",
				mapCallingConvention(fn.Signature.Convention), fn.Signature.ReturnType, len(fn.Signature.Params))
			for idx, p := range fn.Signature.Params {
				fmt.Fprintf(&buf, "        Param [%d]: Type Index %d, Mode (Val/Ref)=%d\n", idx, p.Type, p.Mode)
			}
		} else {
			fmt.Fprintf(&buf, "\nInternal Function [%d]: %s (Bytecode size: %d bytes)\n", fn.Index, fn.Name, len(fn.Bytecode))
			fmt.Fprintf(&buf, "    Signature: CallingConv=%s, ReturnType Index=%d, ParamsCount=%d\n",
				mapCallingConvention(fn.Signature.Convention), fn.Signature.ReturnType, len(fn.Signature.Params))
			for idx, p := range fn.Signature.Params {
				fmt.Fprintf(&buf, "        Param [%d]: Type Index %d, Mode (Val/Ref)=%d\n", idx, p.Type, p.Mode)
			}
			buf.WriteString("    Disassembly:\n")
			disassembleBytecode(&buf, fn.Bytecode)
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
		case OpAssign, OpCalculate, OpCompare:
			// These operators typically consume local variables/constants indices (e.g. 4-8 bytes)
			argSize := 8
			if i+1+argSize <= size {
				fmt.Fprintf(buf, " [Args: % X]", code[i+1:i+1+argSize])
				i += argSize
			}
		case OpPush, OpPushVar, OpPop:
			argSize := 4
			if i+1+argSize <= size {
				fmt.Fprintf(buf, " [Index: %d]", binary.LittleEndian.Uint32(code[i+1:i+1+argSize]))
				i += argSize
			}
		case OpJump, OpJumpTrue, OpJumpFalse:
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
		return "U32 (Cardinal)"
	case TC_S32:
		return "S32 (Integer)"
	case TC_Single:
		return "Single"
	case TC_Double:
		return "Double"
	case TC_Extended:
		return "Extended"
	case TC_AnsiString:
		return "AnsiString"
	case TC_Record:
		return "RECORD"
	case TC_Array:
		return "ARRAY"
	case TC_Pointer:
		return "POINTER"
	case TC_PChar:
		return "PCHAR"
	case TC_ResourcePointer:
		return "RESOURCE_POINTER"
	case TC_Variant:
		return "Variant"
	case TC_S64:
		return "S64 (Int64)"
	case TC_Char:
		return "Char"
	case TC_WideString:
		return "WideString"
	case TC_WideChar:
		return "WideChar"
	case TC_ProcPtr:
		return "PROCPTR"
	case TC_StaticArray:
		return "STATIC_ARRAY"
	case TC_Set:
		return "SET"
	case TC_Currency:
		return "Currency"
	case TC_Class:
		return "CLASS"
	case TC_Interface:
		return "INTERFACE"
	case TC_NotificationVariant:
		return "NotificationVariant"
	case TC_UnicodeString:
		return "UnicodeString"
	case TC_Enum:
		return "ENUM"
	case TC_Type:
		return "TYPE"
	case TC_ExtClass:
		return "EXTCLASS"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", byte(tc))
	}
}

func mapCallingConvention(cc CallingConvention) string {
	switch cc {
	case RegisterCalling:
		return "register"
	case PascalCalling:
		return "pascal"
	case CdeclCalling:
		return "cdecl"
	case StdcallCalling:
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
	case OpPushVar:
		return "PUSHVAR"
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
	case OpJumpTrue:
		return "JUMP_TRUE"
	case OpJumpFalse:
		return "JUMP_FALSE"
	case OpStackType:
		return "STACK_TYPE"
	case OpPushType:
		return "PUSH_TYPE"
	case OpCompare:
		return "COMPARE"
	case OpSetPtr:
		return "SETPTR"
	case OpBooleanNot:
		return "BOOL_NOT"
	case OpNeg:
		return "NEG"
	case OpSetFlag:
		return "SETFLAG"
	case OpJumpFlag:
		return "JUMPFLAG"
	case OpPushEH:
		return "PUSH_EH"
	case OpPopEH:
		return "POP_EH"
	case OpIntegerNot:
		return "INT_NOT"
	case OpSetPtrToCopy:
		return "SETPTRTOCOPY"
	case OpInc:
		return "INC"
	case OpDec:
		return "DEC"
	case OpJumpPop1:
		return "JUMPPOP1"
	case OpJumpPop2:
		return "JUMPPOP2"
	case OpNop:
		return "NOP"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", byte(op))
	}
}
