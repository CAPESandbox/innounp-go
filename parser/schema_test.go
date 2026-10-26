package parser

import (
	"testing"
)

func TestGetRecordSchema_5402(t *testing.T) {
	// 1. Verify TSetupHeader schema lookup for Inno Setup 5.4.2 (ver = 5402) under ANSI
	schema, ok := GetRecordSchema(5402, "TSetupHeader", false)
	if !ok {
		t.Fatalf("failed to retrieve TSetupHeader schema for ver 5402")
	}

	// Under 5.4.2, the first group (Wide/Ansi) has exactly 26 strings.
	// Since isUnicode is false (ANSI), applyAnsiSchemaOverrides converts WideStrings to AnsiStrings:
	// NumAnsiStrings = NumWideStrings + NumAnsiStrings -> 26 + 4 = 30 strings total.
	if schema.NumAnsiStrings != 30 {
		t.Errorf("expected 30 AnsiStrings for ANSI 5402 TSetupHeader, got %d", schema.NumAnsiStrings)
	}
	if schema.NumWideStrings != 0 {
		t.Errorf("expected 0 WideStrings for ANSI 5402 TSetupHeader, got %d", schema.NumWideStrings)
	}

	// Verify LeadBytes is prepended (32 bytes)
	if len(schema.FixedFields) == 0 || schema.FixedFields[0].Name != "LeadBytes" {
		t.Errorf("expected LeadBytes to be prepended to ANSI TSetupHeader fixed fields")
	}

	// Verify Options has size of 7 bytes in 5.4.2
	var optionsField *FieldSchema
	for _, f := range schema.FixedFields {
		if f.Name == "Options" {
			optionsField = &f
			break
		}
	}
	if optionsField == nil {
		t.Fatalf("Options field not found in TSetupHeader fixed fields")
	}
	if optionsField.Size != 7 {
		t.Errorf("expected Options size to be 7 bytes in 5402, got %d", optionsField.Size)
	}

	// 2. Verify TSetupIconEntry schema lookup for Inno Setup 5.4.2 (ver = 5402) under ANSI
	iconSchema, ok := GetRecordSchema(5402, "TSetupIconEntry", false)
	if !ok {
		t.Fatalf("failed to retrieve TSetupIconEntry schema for ver 5402")
	}

	// Under 5.4.2, TSetupIconEntry has 13 WideStrings. Under ANSI, they convert to 13 AnsiStrings.
	if iconSchema.NumAnsiStrings != 13 {
		t.Errorf("expected 13 AnsiStrings for ANSI 5402 TSetupIconEntry, got %d", iconSchema.NumAnsiStrings)
	}

	// 3. Verify TSetupDeleteEntry schema lookup for Inno Setup 5.4.2 (ver = 5402) under ANSI
	deleteSchema, ok := GetRecordSchema(5402, "TSetupDeleteEntry", false)
	if !ok {
		t.Fatalf("failed to retrieve TSetupDeleteEntry schema for ver 5402")
	}

	// Under 5.4.2, TSetupDeleteEntry must NOT contain the "Options" field in its fixed fields
	for _, f := range deleteSchema.FixedFields {
		if f.Name == "Options" {
			t.Errorf("TSetupDeleteEntry in 5.4.2 must not contain 'Options' field")
		}
	}
}

func TestGetRecordSchema_ModernUnicodeLanguageEntry(t *testing.T) {
	for _, ver := range []int{6600, 7000} {
		schema, ok := GetRecordSchema(ver, "TSetupLanguageEntry", true)
		if !ok {
			t.Fatalf("failed to retrieve TSetupLanguageEntry schema for ver %d", ver)
		}
		if schema.NumWideStrings != 4 {
			t.Errorf("expected 4 WideStrings for ver %d TSetupLanguageEntry, got %d", ver, schema.NumWideStrings)
		}
		if schema.NumAnsiStrings != 4 {
			t.Errorf("expected 4 AnsiStrings for ver %d TSetupLanguageEntry, got %d", ver, schema.NumAnsiStrings)
		}

		expectedFields := []string{
			"LanguageID",
			"DialogFontSize",
			"DialogFontBaseScaleHeight",
			"DialogFontBaseScaleWidth",
			"WelcomeFontSize",
			"RightToLeft",
		}
		if len(schema.FixedFields) != len(expectedFields) {
			t.Fatalf("expected %d fixed fields for ver %d, got %d", len(expectedFields), ver, len(schema.FixedFields))
		}
		for i, name := range expectedFields {
			if schema.FixedFields[i].Name != name {
				t.Errorf("expected field %d to be %s, got %s", i, name, schema.FixedFields[i].Name)
			}
		}
	}

	// Verify TSetupPermissionEntry preserves 1 ANSI string in Unicode mode
	permSchema, ok := GetRecordSchema(6600, "TSetupPermissionEntry", true)
	if !ok {
		t.Fatalf("failed to retrieve TSetupPermissionEntry schema")
	}
	if permSchema.NumAnsiStrings != 1 {
		t.Errorf("expected 1 AnsiString for Unicode TSetupPermissionEntry, got %d", permSchema.NumAnsiStrings)
	}

	// Verify TSetupISSigKeyEntry preserves 1 ANSI string in Unicode mode
	for _, ver := range []int{6600, 7000} {
		sigSchema, ok := GetRecordSchema(ver, "TSetupISSigKeyEntry", true)
		if !ok {
			t.Fatalf("failed to retrieve TSetupISSigKeyEntry schema for ver %d", ver)
		}
		if sigSchema.NumAnsiStrings != 1 {
			t.Errorf("expected 1 AnsiString for Unicode TSetupISSigKeyEntry, got %d", sigSchema.NumAnsiStrings)
		}
	}
}
