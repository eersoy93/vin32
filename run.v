module main

fn run_exe(exe_contents string) int
{
	// Classify EXE contents
	pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_import_table, pe32_section_headers, pe_header_pointer, exe_sections_count := parse_exe(exe_contents)

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

	// Load headers and sections to EXE exe_memory
	load_exe(exe_contents, mut &exe_memory, pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_import_table, pe32_section_headers, pe_header_pointer, exe_sections_count)

	// Parse import directories on the EXE exe_memory
	import_directories_address := int(pe32_import_table.address)
	mut pe32_import_descriptors := []PE32_IMPORT_DESCRIPTOR{}
	parse_imports(exe_memory, import_directories_address, mut &pe32_import_descriptors)

	// Print import DLL names and the APIs for debugging
	print_imports(pe32_import_descriptors, exe_memory, pe32_optional_header)

	// Separate opcodes the EXE code from entry point
	entry_point_address := pe32_optional_header.entry_point
	code_size := pe32_optional_header.code_size
	code_part := exe_memory[(entry_point_address)..(entry_point_address + code_size)].clone()

	// Initialize the CPU
	cpu_regs := init_cpu()

	// Execute the EXE code
	println_debug("Executing:")
	execute(entry_point_address, code_size, code_part, exe_memory, cpu_regs)

	// TODO: To be continued!

	// Return if success
	return exit_success
}
