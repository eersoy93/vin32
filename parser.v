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

	// Debugly print pointer to PE header
	pointer_to_pe_header_bytes := exe_contents[60..64].bytes()  // 0x3C == 60
	println_debug("Pointer to PE header in bytes: ${pointer_to_pe_header_bytes}")

	// Check PE signature
	pe_signature_offset := pointer_to_pe_header_bytes[0]
	pe_signature := exe_contents[(pe_signature_offset)..(pe_signature_offset+4)]
	if pe_signature.bytes() == [u8(0x50), 0x45, 0x00, 0x00]
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(1)
	}

}
