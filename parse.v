module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string)
{
	// Classify EXE contents to PE32_DOS_HEADER struct

	pe32_dos_header := PE32_DOS_HEADER
	{
		magic_number:                   u16(exe_contents[0..2].bytes().hex().parse_uint(16, 0) or { return })
		last_page_of_file_bytes:        u16(exe_contents[2..4].bytes().hex().parse_uint(16, 0) or { return })
		pages_in_file:                  u16(exe_contents[4..6].bytes().hex().parse_uint(16, 0) or { return })
		relocations:                    u16(exe_contents[6..8].bytes().hex().parse_uint(16, 0) or { return })
		size_of_header_in_paragraphs:   u16(exe_contents[8..10].bytes().hex().parse_uint(16, 0) or { return })
		extra_paragraphs_needed_min:    u16(exe_contents[10..12].bytes().hex().parse_uint(16, 0) or { return })
		extra_paragraphs_needed_max:    u16(exe_contents[12..14].bytes().hex().parse_uint(16, 0) or { return })
		initial_relative_ss_value:      u16(exe_contents[14..16].bytes().hex().parse_uint(16, 0) or { return })
		initial_sp_value:               u16(exe_contents[16..18].bytes().hex().parse_uint(16, 0) or { return })
		checksum:                       u16(exe_contents[18..20].bytes().hex().parse_uint(16, 0) or { return })
		initial_ip_value:               u16(exe_contents[20..22].bytes().hex().parse_uint(16, 0) or { return })
		initial_relative_cs_value:      u16(exe_contents[22..24].bytes().hex().parse_uint(16, 0) or { return })
		relocation_table_file_address:  u16(exe_contents[24..26].bytes().hex().parse_uint(16, 0) or { return })
		overlay_number:                 u16(exe_contents[26..28].bytes().hex().parse_uint(16, 0) or { return })
		reserved_words:                 [
		                                u16(exe_contents[28..30].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[30..32].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[32..34].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[34..36].bytes().hex().parse_uint(16, 0) or { return })
		                                ]!
		oem_identifier:                 u16(exe_contents[36..38].bytes().hex().parse_uint(16, 0) or { return })
		oem_information:                u16(exe_contents[38..40].bytes().hex().parse_uint(16, 0) or { return })
		reserved_words_2:               [
		                                u16(exe_contents[40..42].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[42..44].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[44..46].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[46..48].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[48..50].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[50..52].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[52..54].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[54..56].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[56..58].bytes().hex().parse_uint(16, 0) or { return }),
		                                u16(exe_contents[58..60].bytes().hex().parse_uint(16, 0) or { return })
		                                ]!
		pointer_to_pe_header:           u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { return })
	}

	x := pe32_dos_header.pointer_to_pe_header

	pe32_file_header := PE32_FILE_HEADER
	{
		nt_signature:            u32(exe_contents[x..(x + 4)].bytes().hex().parse_uint(16, 0) or { return })
		machine_type:            u16(exe_contents[(x + 4)..(x + 6)].bytes().reverse().hex().parse_uint(16, 0) or { return })
		sections_count:          u16(exe_contents[(x + 6)..(x + 8)].bytes().hex().parse_uint(16, 0) or { return })
		time_date_stamp:         u32(exe_contents[(x + 8)..(x + 12)].bytes().hex().parse_uint(16, 0) or { return })
		symbol_table_pointer:    u32(exe_contents[(x + 12)..(x + 16)].bytes().hex().parse_uint(16, 0) or { return })
		number_of_symbols:       u32(exe_contents[(x + 16)..(x + 20)].bytes().hex().parse_uint(16, 0) or { return })
		optional_header_size:    u16(exe_contents[(x + 20)..(x + 22)].bytes().hex().parse_uint(16, 0) or { return })
		characteristics:         u16(exe_contents[(x + 22)..(x + 24)].bytes().reverse().hex().parse_uint(16, 0) or { return })
	}

	pe32_optional_header := PE32_OPTIONAL_HEADER
	{
		magic:                      u16(exe_contents[(x + 24)..(x + 26)].bytes().hex().parse_uint(16, 0) or { return })
		linker_version_major:       u8(exe_contents[(x + 26)..(x + 27)].bytes().hex().parse_uint(16, 0) or { return })
		linker_version_minor:       u8(exe_contents[(x + 27)..(x + 28)].bytes().hex().parse_uint(16, 0) or { return })
		code_size:                  u32(exe_contents[(x + 28)..(x + 32)].bytes().hex().parse_uint(16, 0) or { return })
		initialized_data_size:      u32(exe_contents[(x + 32)..(x + 36)].bytes().hex().parse_uint(16, 0) or { return })
		uninitialized_data_size:    u32(exe_contents[(x + 36)..(x + 40)].bytes().hex().parse_uint(16, 0) or { return })
		entry_point:                u32(exe_contents[(x + 40)..(x + 44)].bytes().hex().parse_uint(16, 0) or { return })
		base_of_code:               u32(exe_contents[(x + 44)..(x + 48)].bytes().hex().parse_uint(16, 0) or { return })
		base_of_data:               u32(exe_contents[(x + 48)..(x + 52)].bytes().hex().parse_uint(16, 0) or { return })
		image_size:                 u32(exe_contents[(x + 52)..(x + 56)].bytes().hex().parse_uint(16, 0) or { return })
		section_alignment:          u32(exe_contents[(x + 56)..(x + 60)].bytes().hex().parse_uint(16, 0) or { return })
		file_alignment:             u32(exe_contents[(x + 60)..(x + 64)].bytes().hex().parse_uint(16, 0) or { return })
		os_version_major:           u16(exe_contents[(x + 64)..(x + 66)].bytes().hex().parse_uint(16, 0) or { return })
		os_version_minor:           u16(exe_contents[(x + 66)..(x + 68)].bytes().hex().parse_uint(16, 0) or { return })
		subsystem_version_major:    u16(exe_contents[(x + 68)..(x + 70)].bytes().hex().parse_uint(16, 0) or { return })
		subsystem_version_minor:    u16(exe_contents[(x + 70)..(x + 72)].bytes().hex().parse_uint(16, 0) or { return })
		win32_version_value:        u16(exe_contents[(x + 72)..(x + 74)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_image:              u32(exe_contents[(x + 74)..(x + 78)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_headers:            u32(exe_contents[(x + 78)..(x + 82)].bytes().hex().parse_uint(16, 0) or { return })
		checksum:                   u32(exe_contents[(x + 82)..(x + 86)].bytes().hex().parse_uint(16, 0) or { return })
		subsystem:                  u32(exe_contents[(x + 86)..(x + 90)].bytes().hex().parse_uint(16, 0) or { return })
		dll_characteristics:        u16(exe_contents[(x + 90)..(x + 92)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_stack_reserve:      u32(exe_contents[(x + 92)..(x + 96)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_stack_commit:       u32(exe_contents[(x + 96)..(x + 100)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_heap_reserve:       u32(exe_contents[(x + 100)..(x + 104)].bytes().hex().parse_uint(16, 0) or { return })
		size_of_heap_commit:        u32(exe_contents[(x + 104)..(x + 108)].bytes().hex().parse_uint(16, 0) or { return })
		loader_flags:               u32(exe_contents[(x + 108)..(x + 112)].bytes().hex().parse_uint(16, 0) or { return })
		rvas_and_sizes_number:      u32(exe_contents[(x + 112)..(x + 116)].bytes().hex().parse_uint(16, 0) or { return })
		export_table:               u32(exe_contents[(x + 116)..(x + 120)].bytes().hex().parse_uint(16, 0) or { return })
		import_table:               u32(exe_contents[(x + 120)..(x + 124)].bytes().hex().parse_uint(16, 0) or { return })
		resource_table:             u32(exe_contents[(x + 124)..(x + 128)].bytes().hex().parse_uint(16, 0) or { return })
		exception_table:            u32(exe_contents[(x + 128)..(x + 132)].bytes().hex().parse_uint(16, 0) or { return })
		certificate_table:          u32(exe_contents[(x + 132)..(x + 136)].bytes().hex().parse_uint(16, 0) or { return })
		base_relocation_table:      u32(exe_contents[(x + 136)..(x + 140)].bytes().hex().parse_uint(16, 0) or { return })
		debug_table:                u32(exe_contents[(x + 140)..(x + 144)].bytes().hex().parse_uint(16, 0) or { return })
		architecture_specific_data: u32(exe_contents[(x + 144)..(x + 148)].bytes().hex().parse_uint(16, 0) or { return })
		rva_of_global_pointer:      u32(exe_contents[(x + 148)..(x + 152)].bytes().hex().parse_uint(16, 0) or { return })
		tls_table:                  u32(exe_contents[(x + 152)..(x + 156)].bytes().hex().parse_uint(16, 0) or { return })
		load_config_table:          u32(exe_contents[(x + 156)..(x + 160)].bytes().hex().parse_uint(16, 0) or { return })
		bound_import_table:         u32(exe_contents[(x + 160)..(x + 164)].bytes().hex().parse_uint(16, 0) or { return })
		import_address_table:       u32(exe_contents[(x + 164)..(x + 168)].bytes().hex().parse_uint(16, 0) or { return })
		delay_import_descriptor:    u32(exe_contents[(x + 168)..(x + 172)].bytes().hex().parse_uint(16, 0) or { return })
		clr_runtime_header:         u32(exe_contents[(x + 172)..(x + 176)].bytes().hex().parse_uint(16, 0) or { return })
	}

	pe32_section_header := PE32_SECTION_HEADER
	{
		name:                   u64(exe_contents[(x + 176)..(x + 182)].bytes().hex().parse_uint(16, 0) or { return })
		virtual_size:           u32(exe_contents[(x + 182)..(x + 186)].bytes().hex().parse_uint(16, 0) or { return })
		virtual_address:        u32(exe_contents[(x + 186)..(x + 190)].bytes().hex().parse_uint(16, 0) or { return })
		sizeof_raw_data:        u32(exe_contents[(x + 190)..(x + 194)].bytes().hex().parse_uint(16, 0) or { return })
		ptr_to_raw_data:        u32(exe_contents[(x + 194)..(x + 198)].bytes().hex().parse_uint(16, 0) or { return })
		ptr_to_relocations:     u32(exe_contents[(x + 198)..(x + 202)].bytes().hex().parse_uint(16, 0) or { return })
		ptr_to_line_numbers:    u32(exe_contents[(x + 202)..(x + 206)].bytes().hex().parse_uint(16, 0) or { return })
		number_of_relocations:  u16(exe_contents[(x + 206)..(x + 208)].bytes().hex().parse_uint(16, 0) or { return })
		number_of_line_numbers: u16(exe_contents[(x + 208)..(x + 210)].bytes().hex().parse_uint(16, 0) or { return })
		characteristics:        u32(exe_contents[(x + 210)..(x + 214)].bytes().hex().parse_uint(16, 0) or { return })
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

	// Check whether image has executable characteristic
	if (pe32_file_header.characteristics & u16(0x02)) != 0
	{
		println_debug("The EXE image is executable!")
	}
	else
	{
		println_error("The EXE image is not executable!")
		vin32_exit(1)
	}
}
