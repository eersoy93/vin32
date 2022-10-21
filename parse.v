module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string)
{
	// Classify EXE contents to PE32 struct
	pe32 := PE32
	{
		pe32_dos_header: struct
		{
			magic_number: u16(exe_contents[0..2].bytes().hex().parse_uint(16, 0) or { return })
			pointer_to_pe_header: u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { return })
		}
		pe32_file_header: struct
		{
			machine_type: u16(exe_contents[220..222].bytes().reverse().hex().parse_uint(16, 0) or { return })
		}
	}

	// Check MZ signature
	if pe32.pe32_dos_header.magic_number == pe32_magic_number
	{
		println_debug("MZ signature found!")
	}
	else
	{
		println_error("MZ signature not found!")
		vin32_exit(1)
	}

	// Check PE signature
	exe_pe_signature := exe_contents[(pe32.pe32_dos_header.pointer_to_pe_header)..(pe32.pe32_dos_header.pointer_to_pe_header + 4)]
	if exe_pe_signature.bytes().hex().parse_uint(16, 0) or { return } == pe32_nt_signature
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(1)
	}

	// Check EXE machine type
	if pe32.pe32_file_header.machine_type == pe32_machine_type_i386
	{
		println_debug("EXE machine type is correct!")
	}
	else
	{
		println_error("EXE machine type is incorrect!")
		vin32_exit(1)
	}

	// Check whether image is executable
	exe_characteristics := exe_contents[238..240].bytes()
	if exe_characteristics[0] & u8(0x02) != 0  // If exe has executable characteristics
	{
		println_debug("EXE image is executable!")
	}
	else
	{
		println_error("EXE image is not executable!")
		vin32_exit(1)
	}

}
