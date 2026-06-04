package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"unsafe"

	"innounp-go/parser"
)

//export ExtractInno
func ExtractInno(filePath *C.char, outDir *C.char, password *C.char) C.int {
	goFilePath := C.GoString(filePath)
	goOutDir := C.GoString(outDir)
	goPassword := C.GoString(password)

	err := parser.ExtractAllFiles(goFilePath, goOutDir, goPassword)
	if err != nil {
		return C.int(-1)
	}
	return C.int(0)
}

//export ListInnoFiles
func ListInnoFiles(filePath *C.char) *C.char {
	goFilePath := C.GoString(filePath)

	jsonStr, err := parser.ListFilesJSON(goFilePath)
	if err != nil {
		return nil
	}

	// C.CString allocates memory on the C heap. Python will receive this pointer
	// and is responsible for freeing it back using FreeString.
	return C.CString(jsonStr)
}

//export CrackInnoPassword
func CrackInnoPassword(filePath *C.char, wordlistJson *C.char) *C.char {
	goFilePath := C.GoString(filePath)
	goWordlistJson := C.GoString(wordlistJson)

	var wordlist []string
	err := json.Unmarshal([]byte(goWordlistJson), &wordlist)
	if err != nil {
		return nil
	}

	res, err := parser.CrackPassword(goFilePath, wordlist)
	if err != nil {
		return nil
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		return nil
	}

	return C.CString(string(resBytes))
}

//export FreeString
func FreeString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}
