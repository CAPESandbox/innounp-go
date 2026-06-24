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
	// Initialize core shared layouts (v5300 Unicode / v5500 Unicode) first to ensure
	// fallback map assignments during init() resolve cleanly to non-nil schemas.
	SchemaRegistry[5300] = map[string]RecordSchema{
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
				{"PasswordHash", FieldBytes, 20}, // v5.3+ uses 20-byte SHA-1 hashes!
				{"PasswordSalt", FieldBytes, 8},
				{"ExtraDiskSpaceRequired", FieldInt64, 8}, // v5.3+ ExtraDiskSpaceRequired is Integer64 (8 bytes!)
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"ArchitecturesAllowed", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt32, 4}, // 5.3.x - 5.4.x UninstallDisplaySize is Cardinal (4 bytes!)
				{"Options", FieldBitset, 6},            // Delphi packs 46 elements of TSetupHeaderOption into exactly 6 bytes!
			},
		},
		"TSetupLanguageEntry": {
			NumWideStrings: 6,
			NumAnsiStrings: 4,
			FixedFields: []FieldSchema{
				{"LanguageID", FieldInt32, 4},
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
				{"SHA1Sum", FieldBytes, 20}, // v5.3+ uses 20-byte TSHA1Digest checksum!
				{"TimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 2},
			},
		},
		"TSetupIconEntry": {
			NumWideStrings: 12, // 12 WideStrings in v5300!
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"IconIndex", FieldInt32, 4},
				{"ShowCmd", FieldInt32, 4},
				{"CloseOnExit", FieldEnum, 1},
				{"HotKey", FieldInt16, 2},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupIniEntry": {
			NumWideStrings: 10,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupRegistryEntry": {
			NumWideStrings: 9, // 9 WideStrings in v5300!
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"RootKey", FieldInt32, 4},
				{"PermissionsEntry", FieldInt16, 2},
				{"Type", FieldEnum, 1},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupDeleteEntry": {
			NumWideStrings: 7, // 7 WideStrings in v5300!
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Type", FieldEnum, 1},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupRunEntry": {
			NumWideStrings: 13,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"ShowCmd", FieldInt32, 4},
				{"WaitUntilIdle", FieldEnum, 1},
				{"Options", FieldBitset, 2},
			},
		},
	}

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
				{"ArchitecturesAllowed", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt64, 8}, // 5.5.0+ UninstallDisplaySize is Integer64 (8 bytes!)
				{"Options", FieldBitset, 6},            // Delphi packs 46 elements of TSetupHeaderOption into exactly 6 bytes!
			},
		},
		"TSetupLanguageEntry":     SchemaRegistry[5300]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[5300]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[5300]["TSetupPermissionEntry"],
		"TSetupTypeEntry": {
			NumWideStrings: 5,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupComponentEntry":    SchemaRegistry[5300]["TSetupComponentEntry"],
		"TSetupTaskEntry":         SchemaRegistry[5300]["TSetupTaskEntry"],
		"TSetupDirEntry":          SchemaRegistry[5300]["TSetupDirEntry"],
		"TSetupFileEntry":         SchemaRegistry[5300]["TSetupFileEntry"],
		"TSetupFileLocationEntry": SchemaRegistry[5300]["TSetupFileLocationEntry"],
		"TSetupIconEntry": {
			NumWideStrings: 13, // 13 WideStrings in v5500! AppUserModelID added
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"IconIndex", FieldInt32, 4},
				{"ShowCmd", FieldInt32, 4},
				{"CloseOnExit", FieldEnum, 1},
				{"HotKey", FieldInt16, 2},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupIni": SchemaRegistry[5300]["TSetupIniEntry"],
		"TSetupRegistryEntry": {
			NumWideStrings: 12, // 12 WideStrings in v5500!
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Hive", FieldInt32, 4},
				{"ValueType", FieldInt32, 4},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupDeleteEntry": {
			NumWideStrings: 7, // 7 WideStrings in v5500!
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Type", FieldEnum, 1},
				{"Options", FieldBitset, 4},
			},
		},
		"TSetupRunEntry": SchemaRegistry[5300]["TSetupRunEntry"],
	}

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
		"TSetupLanguageEntry":     SchemaRegistry[2000]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[2000]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[2000]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[2000]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[2000]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[2000]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[2000]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[2000]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[2000]["TSetupFileLocationEntry"],
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
		"TSetupLanguageEntry":     SchemaRegistry[3000]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[3000]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[3000]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[3000]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[3000]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[3000]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[3000]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[3000]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[3000]["TSetupFileLocationEntry"],
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
		"TSetupLanguageEntry":     SchemaRegistry[4000]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[4000]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[4000]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[4000]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[4000]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[4000]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[4000]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[4000]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[4000]["TSetupFileLocationEntry"],
	}

	// Initialize Schema Registry for Inno Setup 5.1.0/5.2.0 (v5100 series)
	SchemaRegistry[5100] = map[string]RecordSchema{
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
				{"PasswordHash", FieldBytes, 16}, // v5100 and v5200 use 16-byte MD5 hashes!
				{"PasswordSalt", FieldBytes, 8},
				{"ExtraDiskSpaceRequired", FieldInt64, 8}, // ExtraDiskSpaceRequired is Integer64 (8 bytes!) in all 5.x!
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"ArchitecturesAllowed", FieldBitset, 1},
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 1},
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt32, 4}, // 4-byte Cardinal
				{"Options", FieldBitset, 6},            // Delphi packs 46 elements of TSetupHeaderOption into exactly 6 bytes!
			},
		},
		"TSetupLanguageEntry":     SchemaRegistry[5300]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[5300]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[5300]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[5500]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[5300]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[5300]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[5300]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[5300]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[5300]["TSetupFileLocationEntry"],
		"TSetupIconEntry":          SchemaRegistry[5300]["TSetupIconEntry"],
		"TSetupIniEntry":           SchemaRegistry[5300]["TSetupIniEntry"],
		"TSetupRegistryEntry":      SchemaRegistry[5300]["TSetupRegistryEntry"],
		"TSetupDeleteEntry":        SchemaRegistry[5300]["TSetupDeleteEntry"],
		"TSetupRunEntry":           SchemaRegistry[5300]["TSetupRunEntry"],
	}

	// Initialize Schema Registry for Inno Setup 6.3.0 (v6300 series)
	SchemaRegistry[6300] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 32,
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
				{"WizardStyle", FieldEnum, 1},
				{"WizardSizePercentX", FieldInt32, 4},
				{"WizardSizePercentY", FieldInt32, 4},
				{"WizardImageAlphaFormat", FieldEnum, 1},
				{"PasswordHash", FieldBytes, 20}, // TSHA1Digest (20 bytes)
				{"PasswordSalt", FieldBytes, 8},   // TSetupSalt (8 bytes)
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"PrivilegesRequiredOverridesAllowed", FieldBitset, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt64, 8},
				{"Options", FieldBitset, 7},
			},
		},
		"TSetupLanguageEntry":     SchemaRegistry[5500]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[5500]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[5500]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[5500]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[5500]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[5500]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[5500]["TSetupDirEntry"],
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
				{"SourceTimeStamp", FieldBytes, 8},
				{"FileVersionMS", FieldInt32, 4},
				{"FileVersionLS", FieldInt32, 4},
				{"Flags", FieldBitset, 2},
				{"Sign", FieldEnum, 1},
			},
		},
		"TSetupIconEntry": {
			NumWideStrings: 13,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"AppUserModelToastActivatorCLSID", FieldBytes, 16},
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"IconIndex", FieldInt32, 4},
				{"ShowCmd", FieldInt32, 4},
				{"CloseOnExit", FieldEnum, 1},
				{"HotKey", FieldInt16, 2},
				{"Options", FieldBitset, 1},
			},
		},
		"TSetupIniEntry":           SchemaRegistry[5500]["TSetupIniEntry"],
		"TSetupRegistryEntry":      SchemaRegistry[5500]["TSetupRegistryEntry"],
		"TSetupDeleteEntry":        SchemaRegistry[5500]["TSetupDeleteEntry"],
		"TSetupRunEntry":           SchemaRegistry[5500]["TSetupRunEntry"],
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
				{"ArchitecturesAllowed", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 1}, // Packed set of paProcessor (size 1 byte!)
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
		"TSetupIconEntry":          SchemaRegistry[5500]["TSetupIconEntry"],
		"TSetupIniEntry":           SchemaRegistry[5500]["TSetupIniEntry"],
		"TSetupRegistryEntry":      SchemaRegistry[5500]["TSetupRegistryEntry"],
		"TSetupDeleteEntry":        SchemaRegistry[5500]["TSetupDeleteEntry"],
		"TSetupRunEntry":           SchemaRegistry[5500]["TSetupRunEntry"],
	}

	// Initialize Schema Registry for Inno Setup 5.4.x (v5400 series)
	SchemaRegistry[5400] = map[string]RecordSchema{
		"TSetupHeader": {
			NumWideStrings: 26,
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
				{"PasswordHash", FieldBytes, 20},
				{"PasswordSalt", FieldBytes, 8},
				{"ExtraDiskSpaceRequired", FieldInt64, 8},
				{"SlicesPerDisk", FieldInt32, 4},
				{"UninstallLogMode", FieldEnum, 1},
				{"DirExistsWarning", FieldEnum, 1},
				{"PrivilegesRequired", FieldEnum, 1},
				{"ShowLanguageDialog", FieldEnum, 1},
				{"LanguageDetectionMethod", FieldEnum, 1},
				{"CompressMethod", FieldEnum, 1},
				{"ArchitecturesAllowed", FieldBitset, 1},
				{"ArchitecturesInstallIn64BitMode", FieldBitset, 1},
				{"DisableDirPage", FieldEnum, 1},
				{"DisableProgramGroupPage", FieldEnum, 1},
				{"UninstallDisplaySize", FieldInt32, 4},
				{"Options", FieldBitset, 7}, // Adjust set size to 7 bytes for 5.4.x series alignment
			},
		},
		"TSetupLanguageEntry":      SchemaRegistry[5300]["TSetupLanguageEntry"],
		"TSetupCustomMessageEntry": SchemaRegistry[5300]["TSetupCustomMessageEntry"],
		"TSetupPermissionEntry":    SchemaRegistry[5300]["TSetupPermissionEntry"],
		"TSetupTypeEntry":          SchemaRegistry[5300]["TSetupTypeEntry"],
		"TSetupComponentEntry":     SchemaRegistry[5300]["TSetupComponentEntry"],
		"TSetupTaskEntry":          SchemaRegistry[5300]["TSetupTaskEntry"],
		"TSetupDirEntry":           SchemaRegistry[5300]["TSetupDirEntry"],
		"TSetupFileEntry":          SchemaRegistry[5300]["TSetupFileEntry"],
		"TSetupFileLocationEntry":  SchemaRegistry[5300]["TSetupFileLocationEntry"],
		"TSetupIconEntry": {
			NumWideStrings: 13, // 13 WideStrings in 5.4.x series! AppUserModelID was added in 5.4.0
			NumAnsiStrings: 0,
			FixedFields:    SchemaRegistry[5300]["TSetupIconEntry"].FixedFields,
		},
		"TSetupIniEntry":           SchemaRegistry[5300]["TSetupIniEntry"],
		"TSetupRegistryEntry":      SchemaRegistry[5300]["TSetupRegistryEntry"],
		"TSetupDeleteEntry": {
			NumWideStrings: 7,
			NumAnsiStrings: 0,
			FixedFields: []FieldSchema{
				{"MinVersion", FieldBytes, 10},
				{"OnlyBelowVersion", FieldBytes, 10},
				{"Type", FieldEnum, 1},
			},
		},
		"TSetupRunEntry":           SchemaRegistry[5300]["TSetupRunEntry"],
	}

	// For compatibility and simplicity, copy v5500 schemas to other 5.x/6.x ranges
	// if they are minor increments.
	SchemaRegistry[1000] = SchemaRegistry[1000] // v1.x fallback map
	SchemaRegistry[5000] = SchemaRegistry[5100] // v5.x fallback (use 5100 ANSI/Cardinal layout)
	SchemaRegistry[6000] = SchemaRegistry[6300] // v6.x fallback
	SchemaRegistry[9999] = SchemaRegistry[5500] // mock test fallback
	SchemaRegistry[5909] = SchemaRegistry[5500] // mock test fallback 32-bit
}

// GetRecordSchema looks up a registered schema for a specific Inno version and record type,
// dynamically applying ANSI-specific overrides on the fly if isUnicode is false.
func GetRecordSchema(ver int, recordName string, isUnicode bool) (RecordSchema, bool) {
	var schema RecordSchema
	var found bool

	// Exact version check
	if records, ok := SchemaRegistry[ver]; ok {
		if schema, found = records[recordName]; found {
			return applyAnsiSchemaOverrides(schema, recordName, ver, isUnicode), true
		}
	}

	// Fallback to exact major-hundreds block (e.g. 5205 -> 5200)
	majorHundreds := (ver / 100) * 100
	if records, ok := SchemaRegistry[majorHundreds]; ok {
		if schema, found = records[recordName]; found {
			return applyAnsiSchemaOverrides(schema, recordName, ver, isUnicode), true
		}
	}

	// Fallback to exact major-thousands block (e.g. 1321 -> 1000, 4107 -> 4000, 5500 -> 5000)
	majorThousands := (ver / 1000) * 1000
	if records, ok := SchemaRegistry[majorThousands]; ok {
		if schema, found = records[recordName]; found {
			return applyAnsiSchemaOverrides(schema, recordName, ver, isUnicode), true
		}
	}

	// Universal fallback
	if records, ok := SchemaRegistry[5500]; ok {
		if schema, found = records[recordName]; found {
			return applyAnsiSchemaOverrides(schema, recordName, ver, isUnicode), true
		}
	}

	return RecordSchema{}, false
}

// applyAnsiSchemaOverrides dynamically converts WideStrings to AnsiStrings on the fly and
// prepends the 32-byte LeadBytes array to TSetupHeader if the installer format is ANSI (isUnicode == false).
func applyAnsiSchemaOverrides(schema RecordSchema, recordName string, ver int, isUnicode bool) RecordSchema {
	// Allocate a new slice copy of FixedFields to isolate mutations from mutating global shared registry maps!
	oldFields := schema.FixedFields
	schema.FixedFields = make([]FieldSchema, len(oldFields))
	copy(schema.FixedFields, oldFields)

	if isUnicode {
		return schema
	}

	// 1. Convert all WideStrings to AnsiStrings sequentially (Delphi $IFNDEF ISUNICODE)
	schema.NumAnsiStrings = schema.NumWideStrings + schema.NumAnsiStrings
	schema.NumWideStrings = 0

	// 2. Prepend LeadBytes (32 bytes) to TSetupHeader if missing
	if recordName == "TSetupHeader" {
		hasLeadBytes := false
		for _, f := range schema.FixedFields {
			if f.Name == "LeadBytes" {
				hasLeadBytes = true
				break
			}
		}
		if !hasLeadBytes {
			schema.FixedFields = append([]FieldSchema{{"LeadBytes", FieldBytes, 32}}, schema.FixedFields...)
		}
	}

	// 3. Dynamic ANSI counts overrides for specific record layouts:
	if recordName == "TSetupRegistryEntry" && ver >= 5000 {
		schema.NumAnsiStrings = 9
	} else if recordName == "TSetupDeleteEntry" && ver >= 5000 {
		schema.NumAnsiStrings = 7
	} else if recordName == "TSetupLanguageEntry" && ver >= 5000 {
		// ANSI language entry adds LanguageCodePage immediately after LanguageID
		newFields := make([]FieldSchema, 0, len(schema.FixedFields)+1)
		for _, f := range schema.FixedFields {
			newFields = append(newFields, f)
			if f.Name == "LanguageID" {
				newFields = append(newFields, FieldSchema{"LanguageCodePage", FieldInt32, 4})
			}
		}
		schema.FixedFields = newFields
	}

	return schema
}
