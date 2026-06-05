package ifps

// TypeCode represents the binary type-descriptor ID inside CompiledCode.bin.
type TypeCode uint8

const (
	TC_ReturnAddress       TypeCode = 0x00
	TC_U08                 TypeCode = 0x01
	TC_S08                 TypeCode = 0x02
	TC_U16                 TypeCode = 0x03
	TC_S16                 TypeCode = 0x04
	TC_U32                 TypeCode = 0x05
	TC_S32                 TypeCode = 0x06
	TC_Single              TypeCode = 0x07
	TC_Double              TypeCode = 0x08
	TC_Extended            TypeCode = 0x09
	TC_AnsiString          TypeCode = 0x0A
	TC_Record              TypeCode = 0x0B
	TC_Array               TypeCode = 0x0C
	TC_Pointer             TypeCode = 0x0D
	TC_PChar               TypeCode = 0x0E
	TC_ResourcePointer     TypeCode = 0x0F
	TC_Variant             TypeCode = 0x10
	TC_S64                 TypeCode = 0x11
	TC_Char                TypeCode = 0x12
	TC_WideString          TypeCode = 0x13
	TC_WideChar            TypeCode = 0x14
	TC_ProcPtr             TypeCode = 0x15
	TC_StaticArray         TypeCode = 0x16
	TC_Set                 TypeCode = 0x17
	TC_Currency            TypeCode = 0x18
	TC_Class               TypeCode = 0x19
	TC_Interface           TypeCode = 0x1A
	TC_NotificationVariant TypeCode = 0x1B
	TC_UnicodeString       TypeCode = 0x1C
	TC_Enum                TypeCode = 0x81
	TC_Type                TypeCode = 0x82
	TC_ExtClass            TypeCode = 0x83
)

// Op represents an IFPS instruction byte opcode.
type Op uint8

const (
	OpAssign       Op = 0x00
	OpCalculate    Op = 0x01
	OpPush         Op = 0x02
	OpPushVar      Op = 0x03
	OpPop          Op = 0x04
	OpCall         Op = 0x05
	OpJump         Op = 0x06
	OpJumpTrue     Op = 0x07
	OpJumpFalse    Op = 0x08
	OpRet          Op = 0x09
	OpStackType    Op = 0x0A
	OpPushType     Op = 0x0B
	OpCompare      Op = 0x0C
	OpCallVar      Op = 0x0D
	OpSetPtr       Op = 0x0E
	OpBooleanNot   Op = 0x0F
	OpNeg          Op = 0x10
	OpSetFlag      Op = 0x11
	OpJumpFlag     Op = 0x12
	OpPushEH       Op = 0x13
	OpPopEH        Op = 0x14
	OpIntegerNot   Op = 0x15
	OpSetPtrToCopy Op = 0x16
	OpInc          Op = 0x17
	OpDec          Op = 0x18
	OpJumpPop1     Op = 0x19
	OpJumpPop2     Op = 0x1A
	OpNop          Op = 0xFF
)

// Dummy/Unused legacy mappings for backwards compatibility inside mapOpName
const (
	OpJZ  Op = 0xF1
	OpJNZ Op = 0xF2
)

// IFPSParam defines a function parameter type and passing mode (val/ref).
type IFPSParam struct {
	Type uint32
	Mode uint32
}

// IFPSProcSignature holds calling convention, return type, and params list.
type IFPSProcSignature struct {
	Convention CallingConvention
	ReturnType uint32
	Params     []IFPSParam
}

// CallingConvention defines x86 procedure call standard.
type CallingConvention uint8

const (
	RegisterCalling CallingConvention = 0
	PascalCalling   CallingConvention = 1
	CdeclCalling    CallingConvention = 2
	StdcallCalling  CallingConvention = 3
)

// IFPSTypeRecordField stores a field in a record type definition.
type IFPSTypeRecordField struct {
	Type uint32
	Name string
}

// IFPSType represents a parsed CompiledCode type registry entry.
type IFPSType struct {
	Index       uint32
	BaseType    TypeCode
	ElementType uint32                // For arrays and static arrays
	StaticSize  uint32                // For static arrays
	Fields      []IFPSTypeRecordField // For records
	Signature   *IFPSProcSignature    // For ProcPtr
}

// IFPSFunction holds name, signature, and bytecode of a parsed function.
type IFPSFunction struct {
	Index      uint32
	IsExternal bool
	Name       string
	ImportName string
	Signature  IFPSProcSignature
	Bytecode   []byte
}

// IFPSVariable stores a parsed global variable metadata.
type IFPSVariable struct {
	Index uint32
	Type  uint32
	Name  string
}

// IFPSFile holds the entire parsedCompiledCode script.
type IFPSFile struct {
	Magic      [4]byte
	Version    uint32
	EntryPoint uint32
	Types      []IFPSType
	Globals    []IFPSVariable
	Functions  []IFPSFunction
}
