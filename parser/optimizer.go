package parser

// TransformCallInstructions converts relative x86 CALL/JMP target addresses to absolute ones
// (and vice versa if encode is true). This matches Inno Setup's custom BCJ-like filter
// used prior to version 5.3.9.
func TransformCallInstructions(buf []byte, addrOffset uint32, encode bool) {
	if len(buf) < 5 {
		return
	}
	size := len(buf) - 4
	i := 0
	for i < size {
		// E8/E9 are the x86 CALL/JMP opcodes with a relative 32-bit displacement
		if buf[i] == 0xE8 || buf[i] == 0xE9 {
			i++
			// Verify that the highest byte of the displacement is 0x00 or 0xFF.
			// This filters out cases where the byte is just regular data instead of a jump.
			if buf[i+3] == 0x00 || buf[i+3] == 0xFF {
				addr := addrOffset + uint32(i) + 4
				if !encode {
					addr = -addr
				}
				for x := 0; x < 3; x++ {
					addr += uint32(buf[i+x])
					buf[i+x] = byte(addr)
					addr >>= 8
				}
			}
			i += 4
		} else {
			i++
		}
	}
}

// TransformCallInstructions5309 is the updated version of the CALL/JMP filter introduced
// in Inno Setup 5.3.9 (used in modern installers).
func TransformCallInstructions5309(buf []byte, addrOffset uint32, encode bool) {
	if len(buf) < 5 {
		return
	}
	size := len(buf) - 4
	i := 0
	for i < size {
		if buf[i] == 0xE8 || buf[i] == 0xE9 {
			i++
			if buf[i+3] == 0x00 || buf[i+3] == 0xFF {
				addr := (addrOffset + uint32(i) + 4) & 0xFFFFFF
				rel := uint32(buf[i]) | (uint32(buf[i+1]) << 8) | (uint32(buf[i+2]) << 16)
				if !encode {
					rel -= addr
				}
				if (rel & 0x800000) != 0 {
					buf[i+3] = ^buf[i+3]
				}
				if encode {
					rel += addr
				}
				buf[i] = byte(rel)
				buf[i+1] = byte(rel >> 8)
				buf[i+2] = byte(rel >> 16)
			}
			i += 4
		} else {
			i++
		}
	}
}
