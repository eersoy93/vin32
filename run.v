module main

fn run_exe(exe_contents string) int
{
	// Classify EXE contents
	pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers, pe_header_pointer, exe_sections_count := parse_exe(exe_contents)

	// Check some classified EXE content
	check_exe(pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers)

	// Initialize EXE memory
	mut memory := define_memory(pe32_optional_header.size_of_image)
	println_debug("The EXE memory has been initialized.")

	// Load headers to EXE memory

	for i in 0..64  // For EXE DOS Header
	{
		memory[i] = exe_contents[i]
	}

	for i in pe_header_pointer..(pe_header_pointer + 248)  // For EXE File Header AND EXE Optional Header
	{
		memory[i] = exe_contents[i]
	}

	for i in 0..(exe_sections_count)  // For EXE section headers
	{
		for j in 248..288
		{
			memory[pe_header_pointer + 40 * i + j] = exe_contents[pe_header_pointer + 40 * i + j]
		}
	}

	// TODO: To be continued!

	return 0
}
