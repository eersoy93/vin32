module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string)
{
	// Classify EXE contents to PE32_DOS_HEADER struct
	pe32_dos_header := PE32_DOS_HEADER
	{
		magic_number:                  u16(exe_contents[0..2].bytes().hex().parse_uint(16, 0) or { return })
		last_page_of_file_bytes:       u16(exe_contents[2..4].bytes().hex().parse_uint(16, 0) or { return })
		pages_in_file:                 u16(exe_contents[4..6].bytes().hex().parse_uint(16, 0) or { return })
		relocations:                   u16(exe_contents[6..8].bytes().hex().parse_uint(16, 0) or { return })
		size_of_header_in_paragraphs:  u16(exe_contents[8..10].bytes().hex().parse_uint(16, 0) or { return })
		extra_paragraphs_needed_min:   u16(exe_contents[10..12].bytes().hex().parse_uint(16, 0) or { return })
		extra_paragraphs_needed_max:   u16(exe_contents[12..14].bytes().hex().parse_uint(16, 0) or { return })
		initial_relative_ss_value:     u16(exe_contents[14..16].bytes().hex().parse_uint(16, 0) or { return })
		initial_sp_value:              u16(exe_contents[16..18].bytes().hex().parse_uint(16, 0) or { return })
		checksum:                      u16(exe_contents[18..20].bytes().hex().parse_uint(16, 0) or { return })
		initial_ip_value:              u16(exe_contents[20..22].bytes().hex().parse_uint(16, 0) or { return })
		initial_relative_cs_value:     u16(exe_contents[22..24].bytes().hex().parse_uint(16, 0) or { return })
		relocation_table_file_address: u16(exe_contents[24..26].bytes().hex().parse_uint(16, 0) or { return })
		overlay_number:                u16(exe_contents[26..28].bytes().hex().parse_uint(16, 0) or { return })
		reserved_words:                [4]u16{init: 0}  // I couldn't assign valued array to this because V wants [4]u16, not []u16.
		oem_identifier:                u16(exe_contents[36..38].bytes().hex().parse_uint(16, 0) or { return })
		oem_information:               u16(exe_contents[38..40].bytes().hex().parse_uint(16, 0) or { return })
		reserved_words_2:              [10]u16{init: 0}  // I couldn't assign valued array to this because V wants [4]u16, not []u16.
		pointer_to_pe_header:          u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { return })
	}

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
	exe_nt_signature := exe_contents[(pe32_dos_header.pointer_to_pe_header)..(pe32_dos_header.pointer_to_pe_header + 4)]
	if exe_nt_signature.bytes().hex().parse_uint(16, 32) or { return } == pe32_nt_signature
	{
		println_debug("PE signature found!")
	}
	else
	{
		println_error("PE signature not found!")
		vin32_exit(1)
	}

	// Check EXE machine type
	exe_machine_type := exe_contents[(pe32_dos_header.pointer_to_pe_header + 4)..(pe32_dos_header.pointer_to_pe_header + 6)]
	if exe_machine_type.bytes().reverse().hex().parse_uint(16, 16) or { return } == pe32_machine_type_i386
	{
		println_debug("The EXE machine type is correct!")
	}
	else
	{
		println_error("The EXE machine type is incorrect!")
		vin32_exit(1)
	}

	// Check whether image has executable characteristic
	exe_image_characteristics := exe_contents[(pe32_dos_header.pointer_to_pe_header + 22)..(pe32_dos_header.pointer_to_pe_header + 24)]
	if exe_image_characteristics.bytes().reverse().hex().parse_uint(16, 16) or { return } & u16(0x02) != 0
	{
		println_debug("The EXE image is executable!")
	}
	else
	{
		println_error("The EXE image is not executable!")
		vin32_exit(1)
	}
}
