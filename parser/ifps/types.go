package ifps

// TypeCode (TC) represents the category of a Pascal Script type definition.
type TypeCode uint32

const (
	TC_U08           TypeCode = 0x01
	TC_S08           TypeCode = 0x02
	TC_U16           TypeCode = 0x03
	TC_S16           TypeCode = 0x04
	TC_U32           TypeCode = 0x05
	TC_S32           TypeCode = 0x06
	TC_S64           TypeCode = 0x07
	TC_Single        TypeCode = 0x08
	TC_Double        TypeCode = 0x09
	TC_Extended      TypeCode = 0x0A // 10-byte Delphi extended float
	TC_Char          TypeCode = 0x0B
	TC_WideChar      TypeCode = 0x0C
	TC_AnsiString    TypeCode = 0x0D
	TC_UnicodeString TypeCode = 0x0E
	TC_Variant       TypeCode = 0x0F
	TC_Pointer       TypeCode = 0x10
	TC_Record        TypeCode = 0x11
	TC_Array         TypeCode = 0x12
	TC_StaticArray   TypeCode = 0x13
	TC_Set           TypeCode = 0x14
	TC_Currency      TypeCode = 0x15
	TC_Class         TypeCode = 0x16
	TC_Interface     TypeCode = 0x17
	TC_ProcPtr       TypeCode = 0x1A
)

// Op represents executable bytecode instruction opcodes.
type Op byte

const (
	OpAssign               Op = 0x00
	OpCalculate            Op = 0x01
	OpPush                 Op = 0x02
	OpPop                  Op = 0x03
	OpCall                 Op = 0x04
	OpCallVar              Op = 0x05
	OpRet                  Op = 0x06
	OpJump                 Op = 0x07
	OpJZ                   Op = 0x08
	OpJNZ                  Op = 0x09
	OpAnd                  Op = 0x0A
	OpOr                   Op = 0x0B
	OpNot                  Op = 0x0C
	OpMinus                Op = 0x0D
	OpCompare              Op = 0x0E
	OpGetClassProperty     Op = 0x0F
	OpSetClassProperty     Op = 0x10
	OpCreateEvent          Op = 0x11
	OpSetEvent             Op = 0x12
	OpGetEvent             Op = 0x13
	OpIn                   Op = 0x14
	OpIs                   Op = 0x15
	OpAs                   Op = 0x16
	OpCalculateAssigned    Op = 0x17
	OpCalculateNotAssigned Op = 0x18
	OpCalculateEqual       Op = 0x19
	OpCalculateNotEqual    Op = 0x1A
)

// CallingConvention defines how functions are executed on the stack.
type CallingConvention uint32

const (
	CcRegister CallingConvention = 0
	CcPascal   CallingConvention = 1
	CcCdecl    CallingConvention = 2
	CcStdcall  CallingConvention = 3
)

// IFPSType holds a parsed type definition from the types block.
type IFPSType struct {
	Index       uint32
	BaseType    TypeCode
	ElementType uint32              // Used by TArray / TStaticArray
	StaticSize  uint32              // Used by TStaticArray
	Fields      []IFPSTypeRecordField // Used by TRecord
	Signature   *IFPSProcSignature  // Used by TProcPtr
}

type IFPSTypeRecordField struct {
	Name string
	Type uint32
}

// IFPSProcSignature captures parameter layouts and return types for functions/proc pointers.
type IFPSProcSignature struct {
	Convention CallingConvention
	ReturnType uint32
	Params     []IFPSParam
}

type IFPSParam struct {
	Type uint32
	Mode uint32 // byval, byref, var, etc.
}

// IFPSVariable holds global variable indices and names.
type IFPSVariable struct {
	Index uint32
	Type  uint32
	Name  string
}

// IFPSFunction defines an parsed internal or imported function.
type IFPSFunction struct {
	Index      uint32
	IsExternal bool
	Name       string
	ImportName string // DLL/API module name for external functions
	Signature  IFPSProcSignature
	Bytecode   []byte // Executable bytes for internal functions
}

// IFPSFile holds the complete parsed bytecode container of CompiledCode.bin.
type IFPSFile struct {
	Magic     [4]byte // "IFPS"
	Version   uint32
	EntryPoint uint32
	Types     []IFPSType
	Globals   []IFPSVariable
	Functions []IFPSFunction
}
