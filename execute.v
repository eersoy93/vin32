module main

import encoding.binary

// FIXME: The executing opcodes NOT yet implemented!

fn execute(entry_point_address u32, code_size u32, code_part []u8, exe_memory []u8, cpu_regs &CpuRegs) {
	mut current_point_offset := u32(0)
	for current_point_offset < code_size
	{
		mut opcode_size := u8(1)
		match code_part[current_point_offset]
		{
			// XOR Gv, Ev
			0x33
			{
				opcode_size = 2
				match code_part[current_point_offset + 1]
				{
					// XOR EBX, EBX
					0xDB
					{
						asmstr := "XOR EBX, EBX"
						println_debug("    ${asmstr}")
					}
					// XOR ESI, ESI
					0xF6
					{
						asmstr := "XOR ESI, ESI"
						println_debug("....${asmstr}")
					}
					else
					{
						println_error("Invalid or unrecognized ModR/M byte!")
						vin32_exit(exit_failure)
					}
				}
			}
			// PUSH EAX
			0x50
			{
				asmstr := "PUSH EAX"
				println_debug("    ${asmstr}")
			}
			// PUSH ECX
			0x51
			{
				asmstr := "PUSH ECX"
				println_debug("    ${asmstr}")
			}
			// PUSH EDX
			0x52
			{
				asmstr := "PUSH EDX"
				println_debug("    ${asmstr}")
			}
			// PUSH EBX
			0x53
			{
				asmstr := "PUSH EBX"
				println_debug("    ${asmstr}")
			}
			// PUSH ESP
			0x54
			{
				asmstr := "PUSH ESP"
				println_debug("    ${asmstr}")
			}
			// PUSH EBP
			0x55
			{
				asmstr := "PUSH EBP"
				println_debug("    ${asmstr}")
			}
			// PUSH ESI
			0x56
			{
				asmstr := "PUSH ESI"
				println_debug("    ${asmstr}")
			}
			// PUSH EDI
			0x57
			{
				asmstr := "PUSH EDI"
				println_debug("    ${asmstr}")
			}
			// POP EAX
			0x58
			{
				asmstr := "POP EAX"
				println_debug("    ${asmstr}")
			}
			// POP ECX
			0x59
			{
				asmstr := "POP ECX"
				println_debug("    ${asmstr}")
			}
			// POP EDX
			0x5A
			{
				asmstr := "POP EDX"
				println_debug("    ${asmstr}")
			}
			// POP EBX
			0x5B
			{
				asmstr := "POP EBX"
				println_debug("    ${asmstr}")
			}
			// POP ESP
			0x5C
			{
				asmstr := "POP ESP"
				println_debug("    ${asmstr}")
			}
			// POP EBP
			0x5D
			{
				asmstr := "POP EBP"
				println_debug("    ${asmstr}")
			}
			// POP ESI
			0x5E
			{
				asmstr := "POP ESI"
				println_debug("    ${asmstr}")
			}
			// POP EDI
			0x5F
			{
				asmstr := "POP EDI"
				println_debug("    ${asmstr}")
			}
			// Immedaite Grp1 Ev, Iv
			0x81
			{
				opcode_size = 6
				match code_part[current_point_offset + 1]
				{
					// SUB ESP, <immediate word value>
					0xEC
					{
						value_imm := binary.little_endian_u16(code_part[(current_point_offset + 2)..(current_point_offset + 4)])
						asmstr := "SUB ESP, 0x${value_imm}"
				        println_debug("    ${asmstr}")
					}
					else
					{
						println_error("Invalid or unrecognized ModR/M byte!")
						vin32_exit(exit_failure)
					}
				}
			}
			// MOV Ev, Gv
			0x89
			{
				match code_part[current_point_offset + 1..current_point_offset + 3]
				{
					// MOV DWORD PTR [ESP + offset], EAX
					[u8(0x44), 0x24]
					{
						opcode_size = 8
						asmstr := 'MOV DWORD PTR [ESP + 0x${code_part[current_point_offset + 3].hex()}], EaX'
						println_debug('    ${asmstr}')
					}
					// MOV DWORD PTR [ESP + offset], EBX
					[u8(0x5C), 0x24]
					{
						opcode_size = 8
						asmstr := 'MOV DWORD PTR [ESP + 0x${code_part[current_point_offset + 3].hex()}], EBX'
						println_debug('    ${asmstr}')
					}
					else
					{
						println_error('Invalid or unrecognized ModR/M byte!')
						vin32_exit(exit_failure)
					}
				}
			}
			else
			{
				println_error("Invalid or unrecognized opcode!")
				vin32_exit(exit_failure)
			}
		}

		current_point_offset += opcode_size
	}
}
