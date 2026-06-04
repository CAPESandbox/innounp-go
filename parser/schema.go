package parser

// FieldType defines the serialization type of a binary field.
type FieldType int

const (
	FieldWideString FieldType = iota
	FieldAnsiString
	FieldInt8
	FieldInt16
	FieldInt32
	FieldInt64
	FieldBitset // Delphi sets (stores bit flags)
	FieldEnum   // Enums (usually 1 byte on disk)
	FieldBytes  // Raw byte array (e.g. checksums)
)

// FieldSchema represents a single binary field.
type FieldSchema struct {
	Name string
	Type FieldType
	Size int // Used for FieldBytes and FieldBitset to specify byte size
}

// RecordSchema defines the sequential structural layout of an Inno Setup record.
type RecordSchema struct {
	NumWideStrings int
	NumAnsiStrings int
	FixedFields    []FieldSchema
}

// ParsedRecord holds raw decoded values of a parsed record.
type ParsedRecord struct {
	WideStrings []string
	AnsiStrings []string
	Fields      map[string]interface{}
}

// SchemaRegistry maps: InnoVer -> RecordName -> RecordSchema
var SchemaRegistry = map[int]map[string]RecordSchema{}

func init() {
	// Initialize Schema Registry for Inno Setup 1.x (v1000 series)
	SchemaRegistry[1000] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 0,
			NumAnsiStrings: 20,
			FixedFields: []FieldSchema{
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4}, // 10 fields total (no languages, types, comps, tasks)
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4}, // 12 bytes backcolor
				{"Password", FieldInt32, 4},
				{"ExtraDiskSpaceRequired", FieldInt32, 4}, // 32-bit (4 bytes)
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1}, // 2 enums total (no UninstallStyle, InstallMode, etc.)
				{"Options", FieldBitset, 4},        // 25 elements fits in 4 bytes
			},
		},
		"TSetupDirEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 1,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupFileEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3, // only SourceFilename, DestName, InstallFontName in v1
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"LocationEntry", FieldInt32, 4},
				{"Attribs", FieldInt32, 4},
				{"ExternalSize", FieldInt32, 4}, // 32-bit
				{"CopyMode", FieldEnum, 1},
				{"Options", FieldBitset, 4},
				{"FileType", FieldEnum, 1},
			},
		},
		"TSetupFileLocationEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"FirstSlice", FieldInt32, 4},
				{"LastSlice", FieldInt32, 4},
				{"StartOffset", FieldInt32, 4},
				{"OriginalSize", FieldInt32, 4},        // 32-bit
				{"ChunkCompressedSize", FieldInt32, 4}, // 32-bit
				{"SHA1Sum", FieldBytes, 4},             // Adler32 (4 bytes)
				{"TimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 4},
			},
		},
	}

	// Initialize Schema Registry for Inno Setup 2.x (v2000 series)
	SchemaRegistry[2000] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 0,
			NumAnsiStrings: 20, // 20 strings in v2 (v3 has 21)
			FixedFields: []FieldSchema{
				{"LeadBytes", FieldBytes, 32},
				{"NumTypeEntries", FieldInt32, 4},
				{"NumComponentEntries", FieldInt32, 4},
				{"NumTaskEntries", FieldInt32, 4},
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4}, // 13 fields (no PaddingNum)
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4},
				{"WizardSmallImageBackColor", FieldInt32, 4},
				{"Password", FieldInt32, 4},
				{"ExtraDiskSpaceRequired", FieldInt32, 4}, // 32-bit (4 bytes)
				{"InstallMode", FieldEnum, 1},
				{"UninstallLogMode", FieldEnum, 1},
				{"UninstallStyle", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1}, // 4 enums total (no RestartComputer)
				{"Options", FieldBitset, 5},
			},
		},
		"TSetupLanguageEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 5,
			FixedFields: []FieldSchema{
				{"LanguageID", FieldInt32, 4},
				{"DialogFontSize", FieldInt32, 4},
				{"DialogFontStandardHeight", FieldInt32, 4},
				{"TitleFontSize", FieldInt32, 4},
				{"WelcomeFontSize", FieldInt32, 4},
				{"CopyrightFontSize", FieldInt32, 4},
			},
		},
		"TSetupCustomMessageEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 2,
			FixedFields: []FieldSchema{
				{"LanguageEntry", FieldInt32, 4},
			},
		},
		"TSetupPermissionEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 1,
			FixedFields:    []FieldSchema{},
		},
		"TSetupTypeEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 2,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt32, 4},
			},
		},
		"TSetupComponentEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3,
			FixedFields: []FieldSchema{
				{"ExtraDiskSpaceRequired", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt32, 4},
			},
		},
		"TSetupTaskEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupDirEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3,
			FixedFields: []FieldSchema{
				{"Attribs", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupFileEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 5,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"LocationEntry", FieldInt32, 4},
				{"Attribs", FieldInt32, 4},
				{"ExternalSize", FieldInt32, 4},
				{"CopyMode", FieldEnum, 1},
				{"Options", FieldBitset, 4},
				{"FileType", FieldEnum, 1},
			},
		},
		"TSetupFileLocationEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"FirstSlice", FieldInt32, 4},
				{"LastSlice", FieldInt32, 4},
				{"StartOffset", FieldInt32, 4},
				{"OriginalSize", FieldInt32, 4},
				{"ChunkCompressedSize", FieldInt32, 4},
				{"SHA1Sum", FieldBytes, 4}, // Adler32 (4 bytes)
				{"TimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 4},
			},
		},
	}

	// Initialize Schema Registry for Inno Setup 3.x (v3000 series)
	SchemaRegistry[3000] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 0,
			NumAnsiStrings: 21,
			FixedFields: []FieldSchema{
				{"LeadBytes", FieldBytes, 32},
				{"NumTypeEntries", FieldInt32, 4},
				{"NumComponentEntries", FieldInt32, 4},
				{"NumTaskEntries", FieldInt32, 4},
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4},
				{"PaddingNum", FieldInt32, 4}, // keeps count fields aligned to 14 fields
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4},
				{"WizardSmallImageBackColor", FieldInt32, 4},
				{"Password", FieldInt32, 4},
				{"ExtraDiskSpaceRequired", FieldInt32, 4}, // 32-bit (4 bytes) in v3!
				{"InstallMode", FieldEnum, 1},
				{"UninstallLogMode", FieldEnum, 1},
				{"UninstallStyle", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"RestartComputer", FieldEnum, 1},
				{"Options", FieldBitset, 5},
			},
		},
		"TSetupLanguageEntry": { // named TSetupLangOptions in v3
			NumWideStrings: 0,
			NumAnsiStrings: 5,
			FixedFields: []FieldSchema{
				{"LanguageID", FieldInt32, 4},
				{"DialogFontSize", FieldInt32, 4},
				{"DialogFontStandardHeight", FieldInt32, 4},
				{"TitleFontSize", FieldInt32, 4},
				{"WelcomeFontSize", FieldInt32, 4},
				{"CopyrightFontSize", FieldInt32, 4},
			},
		},
		"TSetupCustomMessageEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 2,
			FixedFields: []FieldSchema{
				{"LanguageEntry", FieldInt32, 4},
			},
		},
		"TSetupPermissionEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 1,
			FixedFields:    []FieldSchema{},
		},
		"TSetupTypeEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 2,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt32, 4}, // 32-bit in v3
			},
		},
		"TSetupComponentEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3,
			FixedFields: []FieldSchema{
				{"ExtraDiskSpaceRequired", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt32, 4},
			},
		},
		"TSetupTaskEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupDirEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3,
			FixedFields: []FieldSchema{
				{"Attribs", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupFileEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 5,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"LocationEntry", FieldInt32, 4},
				{"Attribs", FieldInt32, 4},
				{"ExternalSize", FieldInt32, 4}, // 32-bit in v3
				{"CopyMode", FieldEnum, 1},
				{"Options", FieldBitset, 4},
				{"FileType", FieldEnum, 1},
			},
		},
		"TSetupFileLocationEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"FirstSlice", FieldInt32, 4},
				{"LastSlice", FieldInt32, 4},
				{"StartOffset", FieldInt32, 4},
				{"OriginalSize", FieldInt32, 4},        // 32-bit in v3
				{"ChunkCompressedSize", FieldInt32, 4}, // 32-bit in v3
				{"SHA1Sum", FieldBytes, 4},             // Adler32 (4 bytes)
				{"TimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 4},
			},
		},
	}

	// Initialize Schema Registry for Inno Setup 4.x (v4000 series)
	SchemaRegistry[4000] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 0,
			NumAnsiStrings: 23,
			FixedFields: []FieldSchema{
				{"LeadBytes", FieldBytes, 32}, // set of AnsiChar (256 bits)
				{"NumLanguageEntries", FieldInt32, 4},
				{"NumTypeEntries", FieldInt32, 4},
				{"NumComponentEntries", FieldInt32, 4},
				{"NumTaskEntries", FieldInt32, 4},
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4},
				{"WizardSmallImageBackColor", FieldInt32, 4},
				{"Password", FieldInt32, 4},
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"SlicesPerDisk", FieldInt32, 4},
				{"InstallMode", FieldEnum, 1},
				{"UninstallLogMode", FieldEnum, 1},
				{"UninstallStyle", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"Options", FieldBitset, 5},
			},
		},
		"TSetupLanguageEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 7,
			FixedFields: []FieldSchema{
				{"LanguageID", FieldInt32, 4},
				{"DialogFontSize", FieldInt32, 4},
				{"DialogFontStandardHeight", FieldInt32, 4},
				{"TitleFontSize", FieldInt32, 4},
				{"WelcomeFontSize", FieldInt32, 4},
				{"CopyrightFontSize", FieldInt32, 4},
			},
		},
		"TSetupCustomMessageEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 2,
			FixedFields: []FieldSchema{
				{"LanguageEntry", FieldInt32, 4},
			},
		},
		"TSetupPermissionEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 1,
			FixedFields:    []FieldSchema{},
		},
		"TSetupTypeEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 3,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt64, 8},
			},
		},
		"TSetupComponentEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"Level", FieldInt32, 4},
				{"Used", FieldInt8, 1},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
				{"Size", FieldInt64, 8},
			},
		},
		"TSetupTaskEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 5,
			FixedFields: []FieldSchema{
				{"Level", FieldInt32, 4},
				{"Used", FieldInt8, 1},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupDirEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"Attribs", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupFileEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 6,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"LocationEntry", FieldInt32, 4},
				{"Attribs", FieldInt32, 4},
				{"ExternalSize", FieldInt64, 8},
				{"Options", FieldBitset, 4},
				{"FileType", FieldEnum, 1},
			},
		},
		"TSetupFileLocationEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"FirstSlice", FieldInt32, 4},
				{"LastSlice", FieldInt32, 4},
				{"StartOffset", FieldInt32, 4},
				{"ChunkSuboffset", FieldInt64, 8},
				{"OriginalSize", FieldInt64, 8},
				{"ChunkCompressedSize", FieldInt64, 8},
				{"SHA1Sum", FieldBytes, 4}, // Adler32 checksum (4 bytes) in v4
				{"TimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 4},
			},
		},
	}

	// Initialize Schema Registry for Inno Setup 5.5.0u (v5500)
	SchemaRegistry[5500] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 27,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"NumLanguageEntries", FieldInt32, 4},
				{"NumCustomMessageEntries", FieldInt32, 4},
				{"NumPermissionEntries", FieldInt32, 4},
				{"NumTypeEntries", FieldInt32, 4},
				{"NumComponentEntries", FieldInt32, 4},
				{"NumTaskEntries", FieldInt32, 4},
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},       // TSetupVersionData (10 bytes)
				{"OnlyBelowVersion", FieldBytes, 10}, // TSetupVersionData (10 bytes)
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4},
				{"PasswordHash", FieldBytes, 20}, // TSHA1Digest (20 bytes)
				{"PasswordSalt", FieldBytes, 8},   // TSetupSalt (8 bytes)
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"ArchitecturesAllowed", FieldBitset, 4},
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 4},
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt64, 8},
				{"Options", FieldBitset, 8}, // 64-bit Delphi set
			},
		},
		"TSetupLanguageEntry": {
			NumWideStrings: 6,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"LanguageID", FieldInt32, 4},
				{"LanguageCodePage", FieldInt32, 4},
				{"DialogFontSize", FieldInt32, 4},
				{"TitleFontSize", FieldInt32, 4},
				{"WelcomeFontSize", FieldInt32, 4},
				{"CopyrightFontSize", FieldInt32, 4},
				{"RightToLeft", FieldInt8, 1},
			},
		},
		"TSetupCustomMessageEntry": {
			NumWideStrings: 2,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"LanguageEntry", FieldInt32, 4},
			},
		},
		"TSetupPermissionEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 1,
			FixedFields:    []FieldSchema{},
		},
		"TSetupTypeEntry": {
			NumWideStrings: 5,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupComponentEntry": {
			NumWideStrings: 5,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Size", FieldInt64, 8},
				{"PermissionsEntry", FieldInt16, 2},
				{"Options", FieldBitset, 4},
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
			},
		},
		"TSetupTaskEntry": {
			NumWideStrings: 5,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"PermissionsEntry", FieldInt16, 2},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupDirEntry": {
			NumWideStrings: 7,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"Attribs", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"PermissionsEntry", FieldInt16, 2},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupFileEntry": {
			NumWideStrings: 10,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"LocationEntry", FieldInt32, 4},
				{"Attribs", FieldInt32, 4},
				{"ExternalSize", FieldInt64, 8},
				{"PermissionsEntry", FieldInt16, 2},
				{"Options", FieldBitset, 4},
				{"FileType", FieldEnum, 1},
			},
		},
		"TSetupFileLocationEntry": {
			NumWideStrings: 0,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"FirstSlice", FieldInt32, 4},
				{"LastSlice", FieldInt32, 4},
				{"StartOffset", FieldInt32, 4},
				{"ChunkSuboffset", FieldInt64, 8},
				{"OriginalSize", FieldInt64, 8},
				{"ChunkCompressedSize", FieldInt64, 8},
				{"SHA1Sum", FieldBytes, 20},
				{"TimeStamp", FieldBytes, 8}, // TFileTime (8 bytes)
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 4},
			},
		},
	}

	// Initialize Schema Registry for Inno Setup 6.4.0+ (v6400 series with modern cryptography)
	SchemaRegistry[6400] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 27,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"NumLanguageEntries", FieldInt32, 4},
				{"NumCustomMessageEntries", FieldInt32, 4},
				{"NumPermissionEntries", FieldInt32, 4},
				{"NumTypeEntries", FieldInt32, 4},
				{"NumComponentEntries", FieldInt32, 4},
				{"NumTaskEntries", FieldInt32, 4},
				{"NumDirEntries", FieldInt32, 4},
				{"NumFileEntries", FieldInt32, 4},
				{"NumFileLocationEntries", FieldInt32, 4},
				{"NumIconEntries", FieldInt32, 4},
				{"NumIniEntries", FieldInt32, 4},
				{"NumRegistryEntries", FieldInt32, 4},
				{"NumInstallDeleteEntries", FieldInt32, 4},
				{"NumUninstallDeleteEntries", FieldInt32, 4},
				{"NumRunEntries", FieldInt32, 4},
				{"NumUninstallRunEntries", FieldInt32, 4},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"BackColor", FieldInt32, 4},
				{"BackColor2", FieldInt32, 4},
				{"WizardImageBackColor", FieldInt32, 4},
				// TIs64Encryption (48 bytes total replaces PasswordHash & PasswordSalt)
				{"PasswordTest", FieldInt32, 4},            // Integer
				{"EncryptionKDFSalt", FieldBytes, 16},       // TSetupKDFSalt (16 bytes)
				{"EncryptionKDFIterations", FieldInt32, 4}, // Integer
				{"EncryptionBaseNonce", FieldBytes, 24},     // TSetupEncryptionNonce (24 bytes)
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"ArchitecturesAllowed", FieldBitset, 4},
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 4},
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt64, 8},
				{"Options", FieldBitset, 8},
			},
		},
		"TSetupLanguageEntry":     SchemaRegistry[5500]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[5500]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[5500]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[5500]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[5500]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[5500]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[5500]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[5500]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[5500]["TSetupFileLocationEntry"],
	}

	// For compatibility and simplicity, copy v5500 schemas to other 5.x/6.x ranges
	// if they are minor increments.
	SchemaRegistry[1000] = SchemaRegistry[1000] // v1.x fallback map
	SchemaRegistry[5000] = SchemaRegistry[5500] // v5.x fallback
	SchemaRegistry[6000] = SchemaRegistry[5500] // v6.x fallback
}

// GetRecordSchema looks up a registered schema for a specific Inno version and record type.
// Falls back to close/compatible versions if a precise match is not present.
func GetRecordSchema(ver int, recordName string) (RecordSchema, bool) {
	// Exact version check
	if records, ok := SchemaRegistry[ver]; ok {
		if schema, ok := records[recordName]; ok {
			return schema, true
		}
	}

	// Fallback to exact major-hundreds block (e.g. 5205 -> 5200)
	majorHundreds := (ver / 100) * 100
	if records, ok := SchemaRegistry[majorHundreds]; ok {
		if schema, ok := records[recordName]; ok {
			return schema, true
		}
	}

	// Fallback to exact major-thousands block (e.g. 1321 -> 1000, 4107 -> 4000, 5500 -> 5000)
	majorThousands := (ver / 1000) * 1000
	if records, ok := SchemaRegistry[majorThousands]; ok {
		if schema, ok := records[recordName]; ok {
			return schema, true
		}
	}

	// Universal fallback
	if records, ok := SchemaRegistry[5500]; ok {
		if schema, ok := records[recordName]; ok {
			return schema, true
		}
	}

	return RecordSchema{}, false
}
