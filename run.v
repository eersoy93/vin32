module main

fn run_exe(exe_contents string) int
{
	// Classify EXE contents
	pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers, x, exe_sections_count := parse_exe(exe_contents)

	// Check MZ signature
	if pe32_dos_header.magic_number == pe32_magic_number
	{
		println_debug("MZ signature found!")
	}
	else
	{
		println_error("MZ signature not found!")
		vin32_exit(1)
	}

	// Check PE signature
	if pe32_file_header.nt_signature == pe32_nt_signature
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(1)
	}

	// Check EXE machine type
	if pe32_file_header.machine_type == pe32_machine_type_i386
	{
		println_debug("The EXE machine type is correct!")
	}
	else
	{
		println_error("The EXE machine type is incorrect!")
		vin32_exit(1)
	}

	// Debugly print EXE sections count
	println_debug("Sections count of the EXE is: ${pe32_file_header.sections_count}")

	// Check whether image has executable characteristic
	if pe32_file_header.characteristics & u16(0x02) != 0
	{
		println_debug("The EXE image is executable!")
	}
	else
	{
		println_error("The EXE image is not executable!")
		vin32_exit(1)
	}

	if pe32_file_header.optional_header_size != sizeof(pe32_optional_header)
	{
		println_warning("SizeOfOptionalHeader doesn't equal with size of the optional header.")
	}

	// Check whether image is PE32 image, not PE32+ or other
	if pe32_optional_header.magic == pe32_optional_magic
	{
		println_debug("The EXE image is PE32 (NT32) image!")
	}
	else
	{
		println_error("The EXE image is not PE32 (NT32) image!")
		vin32_exit(1)
	}

	// Debugly print image section names
	for i, pe32_section_header in pe32_section_headers
	{
		name := pe32_section_header.name[..]
		println_debug("The EXE section name #${i + 1} is: ${name.bytestr()}")
	}

	// Debugly print the image base and image size
	println_debug("The EXE image base is: 0x${pe32_optional_header.image_base.hex()}")
	println_debug("The EXE image size is: ${pe32_optional_header.size_of_image} bytes")

	// Initialize EXE memory
	mut memory := define_memory(pe32_optional_header.size_of_image)
	println_debug("The EXE memory has been initialized.")

	// Load headers to EXE memory

	for i in 0..64  // For EXE DOS Header
	{
		memory[i] = exe_contents[i]
	}

	for i in x..(x + 248)  // For EXE File Header AND EXE Optional Header
	{
		memory[i] = exe_contents[i]
	}

	for i in 0..(exe_sections_count)  // For EXE section headers
	{
		for j in 248..288
		{
			memory[x + 40 * i + j] = exe_contents[x + 40 * i + j]
		}
	}

	// TODO: Running code goes here!

	return 0
}
