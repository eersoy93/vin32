module main

fn run_exe(exe_contents string) int
{
	// Classify EXE contents
	pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers, pe_header_pointer, exe_sections_count := parse_exe(exe_contents)

	// Check some classified EXE content
	check_exe(pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers)

	// Initialize EXE exe_memory
	mut exe_memory := init_exe_memory(pe32_optional_header.size_of_image)
	if exe_memory.len == pe32_optional_header.size_of_image
	{
		println_debug("The EXE exe_memory has been initialized with EXE image size bytes.")
	}
	else
	{
		println_error("The EXE exe_memory has not been initialized with EXE image size bytes.")
	}

	// Load headers to EXE exe_memory

	for i in 0..64  // For EXE DOS Header
	{
		exe_memory[i] = exe_contents[i]
	}

	for i in pe_header_pointer..(pe_header_pointer + 248)  // For EXE File Header AND EXE Optional Header
	{
		exe_memory[i] = exe_contents[i]
	}

	for i in 0..(exe_sections_count)  // For EXE section headers
	{
		for j in 248..288
		{
			exe_memory[pe_header_pointer + 40 * i + j] = exe_contents[pe_header_pointer + 40 * i + j]
		}
	}

	// Load sections to EXE exe_memory
	for section in pe32_section_headers
	{
		for j in 0..(section.sizeof_raw_data)
		{
			exe_memory[section.virtual_address + j] = exe_contents[section.ptr_to_raw_data + j]
		}
		name := section.name[..]
		println_debug("${name.bytestr()} section has been loaded.")
	}

	// Parse import directories on the EXE exe_memory
	import_directories_address := int(pe32_optional_header.import_table.address)
	mut pe32_import_descriptors := []PE32_IMPORT_DESCRIPTOR{}
	for i in 0..32767  // A hardcoded arbitrary big number
	{
		pe32_import_descriptor := PE32_IMPORT_DESCRIPTOR
			{
				original_first_thunk: u32(exe_memory[(import_directories_address + i * 20)..(import_directories_address + i * 20 + 4)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				time_date_stamp:      u32(exe_memory[(import_directories_address + i * 20 + 4)..(import_directories_address + i * 20 + 8)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				forwarder:            u32(exe_memory[(import_directories_address + i * 20 + 8)..(import_directories_address + i * 20 + 12)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				rva_of_name:          u32(exe_memory[(import_directories_address + i * 20 + 12)..(import_directories_address + i * 20 + 16)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				first_thunk:          u32(exe_memory[(import_directories_address + i * 20 + 16)..(import_directories_address + i * 20 + 20)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		if pe32_import_descriptor.original_first_thunk == u32(0x00000000)
		{
			break
		}
		else
		{
			pe32_import_descriptors << pe32_import_descriptor
		}
	}

	// Print import DLL names and the APIs for debugging
	for pe32_import_descriptor in pe32_import_descriptors
	{
		mut dll_name_len := u8(0)
		for j in exe_memory[(pe32_import_descriptor.rva_of_name)..(pe32_import_descriptor.rva_of_name + 255)]
		{
			if j == u8(0)
			{
				break
			}
			dll_name_len++
		}
		println_debug("DLL is required for the APIs below: ${exe_memory[(pe32_import_descriptor.rva_of_name)..(pe32_import_descriptor.rva_of_name + dll_name_len)].bytestr()}")

		for j in 0..4096
		{
			import_address := u32(exe_memory[(pe32_import_descriptor.first_thunk + 4 * j)..(pe32_import_descriptor.first_thunk + 4 * j + 4)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			if import_address == 0
			{
				break
			}
			import_name_address_start := import_address + 2
			mut import_name_address_end := import_name_address_start
			if import_name_address_start > pe32_optional_header.size_of_image
			{
				continue
			}
			for _ in 0..255
			{
				if exe_memory[import_name_address_end] == 0
				{
					break
				}
				import_name_address_end++
			}
			println_debug("    ${exe_memory[import_name_address_start..import_name_address_end].bytestr()}")
		}
	}

	// Disassemble the EXE code from entry point

	entry_point_address := pe32_optional_header.entry_point
	code_size := pe32_optional_header.code_size
	code_part := exe_memory[(entry_point_address)..(entry_point_address + code_size)].clone()
	mut opcodes := []string{}

	println_debug("Codes to be executed:")
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
						opcodes << asmstr
					}
					// XOR ESI, ESI
					0xF6
					{
						asmstr := "XOR ESI, ESI"
						println_debug("....${asmstr}")
						opcodes << asmstr
					}
					else
					{
						println_error("Invalid or unrecognized ModR/M byte!")
						println_debug(opcodes.str())
						vin32_exit(1)
					}
				}
			}
			// PUSH EAX
			0x50
			{
				asmstr := "PUSH EAX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH ECX
			0x51
			{
				asmstr := "PUSH ECX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH EDX
			0x52
			{
				asmstr := "PUSH EDX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH EBX
			0x53
			{
				asmstr := "PUSH EBX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH ESP
			0x54
			{
				asmstr := "PUSH ESP"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH EBP
			0x55
			{
				asmstr := "PUSH EBP"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH ESI
			0x56
			{
				asmstr := "PUSH ESI"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// PUSH EDI
			0x57
			{
				asmstr := "PUSH EDI"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP EAX
			0x58
			{
				asmstr := "POP EAX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP ECX
			0x59
			{
				asmstr := "POP ECX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP EDX
			0x5A
			{
				asmstr := "POP EDX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP EBX
			0x5B
			{
				asmstr := "POP EBX"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP ESP
			0x5C
			{
				asmstr := "POP ESP"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP EBP
			0x5D
			{
				asmstr := "POP EBP"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP ESI
			0x5E
			{
				asmstr := "POP ESI"
				println_debug("    ${asmstr}")
				opcodes << asmstr
			}
			// POP EDI
			0x5F
			{
				asmstr := "POP EDI"
				println_debug("    ${asmstr}")
				opcodes << asmstr
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
						value_imm := u16(code_part[(current_point_offset + 2)..(current_point_offset + 4)].reverse().hex().parse_uint(10, 0) or { panic(panic_text) })
						asmstr := "SUB ESP, 0x${value_imm}"
				        println_debug("    ${asmstr}")
				        opcodes << asmstr
					}
					else
					{
						println_error("Invalid or unrecognized ModR/M byte!")
						println_debug(opcodes.str())
						vin32_exit(1)
					}
				}
			}
			else
			{
				println_error("Invalid or unrecognized opcode!")
				println_debug(opcodes.str())
				vin32_exit(1)
			}
		}

		current_point_offset += opcode_size
	}

	// TODO: To be continued!

	return 0
}
