module main

fn load_exe(exe_contents string, mut exe_memory []u8, pe32_dos_header PE32_DOS_HEADER, pe32_file_header PE32_FILE_HEADER, pe32_optional_header PE32_OPTIONAL_HEADER, pe32_section_headers []PE32_SECTION_HEADER, pe_header_pointer u32, exe_sections_count int)
{
	// Load headers to EXE exe_memory
	println_debug("Loading DOS header to EXE memory...")
	for i in 0..64  // For EXE DOS Header
	{
		exe_memory[i] = exe_contents[i]
	}

	println_debug("Loading PE header to EXE memory...")
	for i in pe_header_pointer..(pe_header_pointer + 248)  // For EXE File Header AND EXE Optional Header
	{
		exe_memory[i] = exe_contents[i]
	}

	println_debug("Loading section headers to EXE memory...")
	for i in 0..(exe_sections_count)  // For EXE section headers
	{
		for j in 248..288
		{
			exe_memory[pe_header_pointer + 40 * i + j] = exe_contents[pe_header_pointer + 40 * i + j]
		}
	}

	// Load sections to EXE exe_memory
	println_debug("Loading sections to EXE memory...")
	for section in pe32_section_headers
	{
		for j in 0..(section.sizeof_raw_data)
		{
			exe_memory[section.virtual_address + j] = exe_contents[section.ptr_to_raw_data + j]
		}
		name := section.name[..]
		println_debug("${name.bytestr()} section has been loaded.")
	}
}
