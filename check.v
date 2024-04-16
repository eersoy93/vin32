module main

fn check_exe(pe32_dos_header PE32_DOS_HEADER, pe32_file_header PE32_FILE_HEADER, pe32_optional_header PE32_OPTIONAL_HEADER, pe32_section_headers []PE32_SECTION_HEADER)
{
	// Check MZ signature
	if pe32_dos_header.magic_number == pe32_magic_number
	{
		println_debug("MZ signature found!")
	}
	else
	{
		println_error("MZ signature not found!")
		vin32_exit(exit_failure)
	}

	// Check PE signature
	if pe32_file_header.nt_signature == pe32_nt_signature
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(exit_failure)
	}

	// Check EXE machine type
	if pe32_file_header.machine_type == pe32_machine_type_i386
	{
		println_debug("The EXE machine type is correct!")
	}
	else
	{
		println_error("The EXE machine type is incorrect!")
		vin32_exit(exit_failure)
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
		vin32_exit(exit_failure)
	}

	// Check SizeOfOptionalHeader equals sizeof(PE32_OPTIONAL_HEADER of the EXE)
	size_of_the_optional_header := sizeof(pe32_optional_header) + pe32_optional_header.rvas_and_sizes_number * 8
	if pe32_file_header.optional_header_size != size_of_the_optional_header
	{
		println_warning("SizeOfOptionalHeader doesn't equal with size of the optional header.")
		println_warning("SizeOfOptionalHeader: ${pe32_file_header.optional_header_size}")
		println_warning("Size of the optional header: ${size_of_the_optional_header}")
	}

	// Check whether image is PE32 image, not PE32+ or other
	if pe32_optional_header.magic == pe32_optional_magic
	{
		println_debug("The EXE image is PE32 (NT32) image!")
	}
	else
	{
		println_error("The EXE image is not PE32 (NT32) image!")
		vin32_exit(exit_failure)
	}

	if pe32_optional_header.rvas_and_sizes_number > 16
	{
		println_warning("NumberOfRvaAndSizes is greater than 16!")
	}

	// Debugly print image section names
	for i, pe32_section_header in pe32_section_headers
	{
		name := pe32_section_header.name
		println_debug("The EXE section name #${i + 1} is: ${name.bytestr()}")
	}

	// Debugly print the image base and image size
	println_debug("The EXE image base is: 0x${pe32_optional_header.image_base.hex()}")
	println_debug("The EXE image size is: ${pe32_optional_header.size_of_image} bytes")
}
