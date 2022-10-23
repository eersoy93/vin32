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
			last_page_of_file_bytes: u16(exe_contents[2..4].bytes().hex().parse_uint(16, 0) or { return })
			pages_in_file: u16(exe_contents[4..6].bytes().hex().parse_uint(16, 0) or { return })
			relocations: u16(exe_contents[6..8].bytes().hex().parse_uint(16, 0) or { return })
			size_of_header_in_paragraphs: u16(exe_contents[8..10].bytes().hex().parse_uint(16, 0) or { return })
			extra_paragraphs_needed_min: u16(exe_contents[10..12].bytes().hex().parse_uint(16, 0) or { return })
			extra_paragraphs_needed_max: u16(exe_contents[12..14].bytes().hex().parse_uint(16, 0) or { return })
			initial_relative_ss_value: u16(exe_contents[14..16].bytes().hex().parse_uint(16, 0) or { return })
			initial_sp_value: u16(exe_contents[16..18].bytes().hex().parse_uint(16, 0) or { return })
			checksum: u16(exe_contents[18..20].bytes().hex().parse_uint(16, 0) or { return })
			initial_ip_value: u16(exe_contents[20..22].bytes().hex().parse_uint(16, 0) or { return })
			initial_relative_cs_value: u16(exe_contents[22..24].bytes().hex().parse_uint(16, 0) or { return })
			relocation_table_file_address: u16(exe_contents[24..26].bytes().hex().parse_uint(16, 0) or { return })
			overlay_number: u16(exe_contents[26..28].bytes().hex().parse_uint(16, 0) or { return })
			// reserved_words:
			// [
			// 	u16(exe_contents[28..30].bytes().hex().parse_uint(16, 0) or { return }),
			// 	u16(exe_contents[30..32].bytes().hex().parse_uint(16, 0) or { return }),
			// 	u16(exe_contents[32..34].bytes().hex().parse_uint(16, 0) or { return }),
			// 	u16(exe_contents[34..36].bytes().hex().parse_uint(16, 0) or { return })
			// ]
			pointer_to_pe_header: u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { return })
		}
		pe32_file_header: struct
		{
			machine_type: u16(exe_contents[220..222].bytes().reverse().hex().parse_uint(16, 0) or { return })
			characteristics: u16(exe_contents[238..240].bytes().reverse().hex().parse_uint(16, 0) or { return })
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
		println_debug("The EXE machine type is correct!")
	}
	else
	{
		println_error("The EXE machine type is incorrect!")
		vin32_exit(1)
	}

	// Check whether image has executable characteristic
	if pe32.pe32_file_header.characteristics & u16(0x02) != 0
	{
		println_debug("The EXE image is executable!")
	}
	else
	{
		println_error("The EXE image is not executable!")
		vin32_exit(1)
	}

}
