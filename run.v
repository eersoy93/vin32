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

	// Parse imports on the EXE exe_memory
	import_directories_address := pe32_optional_header.import_table.address
	import_directories_size := pe32_optional_header.import_table.size
	import_directories_count := import_directories_size / sizeof(PE32_IMPORT_DESCRIPTOR)
	pe32_import_descriptors := []PE32_IMPORT_DESCRIPTOR
	{ len: int(import_directories_count), cap: int(import_directories_count), init: PE32_IMPORT_DESCRIPTOR
		{
			original_first_thunk: u32(exe_memory[(import_directories_address + u32(it) * import_directories_size)..(import_directories_address + u32(it) * import_directories_size + 4)].reverse().hex().parse_uint(16, 0) or { panic })
			time_date_stamp:      u32(exe_memory[(import_directories_address + u32(it) * import_directories_size + 4)..(import_directories_address + u32(it) * import_directories_size + 8)].reverse().hex().parse_uint(16, 0) or { panic })
			forwarder:            u32(exe_memory[(import_directories_address + u32(it) * import_directories_size + 8)..(import_directories_address + u32(it) * import_directories_size + 12)].reverse().hex().parse_uint(16, 0) or { panic })
			rva_of_name:          u32(exe_memory[(import_directories_address + u32(it) * import_directories_size + 12)..(import_directories_address + u32(it) * import_directories_size + 16)].reverse().hex().parse_uint(16, 0) or { panic })
			first_thunk:          u32(exe_memory[(import_directories_address + u32(it) * import_directories_size + 16)..(import_directories_address + u32(it) * import_directories_size + 20)].reverse().hex().parse_uint(16, 0) or { panic })
		}
	}

	// TODO: To be continued!

	return 0
}
