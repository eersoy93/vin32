module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string)
{
	// Check MZ signature
	if exe_contents[0..2].bytes() == [u8(0x4D), 0x5A]  // 4D 5A == "MZ"
	{
		println_debug("MZ signature found!")
	}
	else
	{
		println_error("MZ signature not found!")
		vin32_exit(1)
	}

	// Check PE signature
	pointer_to_pe_header_bytes := exe_contents[60..64].bytes()  // 0x3C == 60
	pe_signature_offset := pointer_to_pe_header_bytes[0]
	pe_signature := exe_contents[(pe_signature_offset)..(pe_signature_offset+4)]
	if pe_signature.bytes() == [u8(0x50), 0x45, 0x00, 0x00]  // "PE\0\0"
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(1)
	}

	// Check EXE machine type
	if exe_contents[220..222].bytes() == [u8(0x4C), 0x01]  // If machine type is Intel 386 and above (0x14c)
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
