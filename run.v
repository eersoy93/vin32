module main

// For 32-bit PE exe files only currently
fn run_exe(exe_contents string) int
{
	// Classify EXE contents to PE32_DOS_HEADER struct

	pe32_dos_header := PE32_DOS_HEADER
	{
		magic_number:                   u16(exe_contents[0..2].bytes().hex().parse_uint(16, 0) or { panic })
		last_page_of_file_bytes:        u16(exe_contents[2..4].bytes().hex().parse_uint(16, 0) or { panic })
		pages_in_file:                  u16(exe_contents[4..6].bytes().hex().parse_uint(16, 0) or { panic })
		relocations:                    u16(exe_contents[6..8].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_header_in_paragraphs:   u16(exe_contents[8..10].bytes().hex().parse_uint(16, 0) or { panic })
		extra_paragraphs_needed_min:    u16(exe_contents[10..12].bytes().hex().parse_uint(16, 0) or { panic })
		extra_paragraphs_needed_max:    u16(exe_contents[12..14].bytes().hex().parse_uint(16, 0) or { panic })
		initial_relative_ss_value:      u16(exe_contents[14..16].bytes().hex().parse_uint(16, 0) or { panic })
		initial_sp_value:               u16(exe_contents[16..18].bytes().hex().parse_uint(16, 0) or { panic })
		checksum:                       u16(exe_contents[18..20].bytes().hex().parse_uint(16, 0) or { panic })
		initial_ip_value:               u16(exe_contents[20..22].bytes().hex().parse_uint(16, 0) or { panic })
		initial_relative_cs_value:      u16(exe_contents[22..24].bytes().hex().parse_uint(16, 0) or { panic })
		relocation_table_file_address:  u16(exe_contents[24..26].bytes().hex().parse_uint(16, 0) or { panic })
		overlay_number:                 u16(exe_contents[26..28].bytes().hex().parse_uint(16, 0) or { panic })
		reserved_words:                 [
		                                u16(exe_contents[28..30].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[30..32].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[32..34].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[34..36].bytes().hex().parse_uint(16, 0) or { panic })
		                                ]!
		oem_identifier:                 u16(exe_contents[36..38].bytes().hex().parse_uint(16, 0) or { panic })
		oem_information:                u16(exe_contents[38..40].bytes().hex().parse_uint(16, 0) or { panic })
		reserved_words_2:               [
		                                u16(exe_contents[40..42].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[42..44].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[44..46].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[46..48].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[48..50].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[50..52].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[52..54].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[54..56].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[56..58].bytes().hex().parse_uint(16, 0) or { panic }),
		                                u16(exe_contents[58..60].bytes().hex().parse_uint(16, 0) or { panic })
		                                ]!
		pointer_to_pe_header:           u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { panic })
	}

	x := pe32_dos_header.pointer_to_pe_header

	pe32_file_header := PE32_FILE_HEADER
	{
		nt_signature:            u32(exe_contents[x..(x + 4)].bytes().hex().parse_uint(16, 0) or { panic })
		machine_type:            u16(exe_contents[(x + 4)..(x + 6)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		sections_count:          u16(exe_contents[(x + 6)..(x + 8)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		time_date_stamp:         u32(exe_contents[(x + 8)..(x + 12)].bytes().hex().parse_uint(16, 0) or { panic })
		symbol_table_pointer:    u32(exe_contents[(x + 12)..(x + 16)].bytes().hex().parse_uint(16, 0) or { panic })
		number_of_symbols:       u32(exe_contents[(x + 16)..(x + 20)].bytes().hex().parse_uint(16, 0) or { panic })
		optional_header_size:    u16(exe_contents[(x + 20)..(x + 22)].bytes().hex().parse_uint(16, 0) or { panic })
		characteristics:         u16(exe_contents[(x + 22)..(x + 24)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
	}

	pe32_optional_header := PE32_OPTIONAL_HEADER
	{
		magic:                      u16(exe_contents[(x + 24)..(x + 26)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		linker_version_major:       u8(exe_contents[(x + 26)..(x + 27)].bytes().hex().parse_uint(16, 0) or { panic })
		linker_version_minor:       u8(exe_contents[(x + 27)..(x + 28)].bytes().hex().parse_uint(16, 0) or { panic })
		code_size:                  u32(exe_contents[(x + 28)..(x + 32)].bytes().hex().parse_uint(16, 0) or { panic })
		initialized_data_size:      u32(exe_contents[(x + 32)..(x + 36)].bytes().hex().parse_uint(16, 0) or { panic })
		uninitialized_data_size:    u32(exe_contents[(x + 36)..(x + 40)].bytes().hex().parse_uint(16, 0) or { panic })
		entry_point:                u32(exe_contents[(x + 40)..(x + 44)].bytes().hex().parse_uint(16, 0) or { panic })
		base_of_code:               u32(exe_contents[(x + 44)..(x + 48)].bytes().hex().parse_uint(16, 0) or { panic })
		base_of_data:               u32(exe_contents[(x + 48)..(x + 52)].bytes().hex().parse_uint(16, 0) or { panic })
		image_base:                 u32(exe_contents[(x + 52)..(x + 56)].bytes().hex().parse_uint(16, 0) or { panic })
		section_alignment:          u32(exe_contents[(x + 56)..(x + 60)].bytes().hex().parse_uint(16, 0) or { panic })
		file_alignment:             u32(exe_contents[(x + 60)..(x + 64)].bytes().hex().parse_uint(16, 0) or { panic })
		os_version_major:           u16(exe_contents[(x + 64)..(x + 66)].bytes().hex().parse_uint(16, 0) or { panic })
		os_version_minor:           u16(exe_contents[(x + 66)..(x + 68)].bytes().hex().parse_uint(16, 0) or { panic })
		image_version_major:        u16(exe_contents[(x + 68)..(x + 70)].bytes().hex().parse_uint(16, 0) or { panic })
		image_version_minor:        u16(exe_contents[(x + 70)..(x + 72)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem_version_major:    u16(exe_contents[(x + 72)..(x + 74)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem_version_minor:    u16(exe_contents[(x + 74)..(x + 76)].bytes().hex().parse_uint(16, 0) or { panic })
		win32_version_value:        u32(exe_contents[(x + 76)..(x + 80)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_image:              u32(exe_contents[(x + 80)..(x + 84)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_headers:            u32(exe_contents[(x + 84)..(x + 88)].bytes().hex().parse_uint(16, 0) or { panic })
		checksum:                   u32(exe_contents[(x + 88)..(x + 92)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem:                  u16(exe_contents[(x + 92)..(x + 94)].bytes().hex().parse_uint(16, 0) or { panic })
		dll_characteristics:        u16(exe_contents[(x + 94)..(x + 96)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_stack_reserve:      u32(exe_contents[(x + 96)..(x + 100)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_stack_commit:       u32(exe_contents[(x + 100)..(x + 104)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_heap_reserve:       u32(exe_contents[(x + 104)..(x + 108)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_heap_commit:        u32(exe_contents[(x + 108)..(x + 112)].bytes().hex().parse_uint(16, 0) or { panic })
		loader_flags:               u32(exe_contents[(x + 112)..(x + 116)].bytes().hex().parse_uint(16, 0) or { panic })
		rvas_and_sizes_number:      u32(exe_contents[(x + 116)..(x + 120)].bytes().hex().parse_uint(16, 0) or { panic })
		export_table:               struct
			{
				u32(exe_contents[(x + 120)..(x + 124)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 124)..(x + 128)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		import_table:               struct
			{
				u32(exe_contents[(x + 128)..(x + 132)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 132)..(x + 136)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		resource_table:             struct
			{
				u32(exe_contents[(x + 136)..(x + 140)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 140)..(x + 144)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		exception_table:            struct
			{
				u32(exe_contents[(x + 144)..(x + 148)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 148)..(x + 152)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		certificate_table:          struct
			{
				u32(exe_contents[(x + 152)..(x + 156)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 156)..(x + 160)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		base_relocation_table:      struct
			{
				u32(exe_contents[(x + 160)..(x + 164)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 164)..(x + 168)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		debug_table:                struct
			{
				u32(exe_contents[(x + 168)..(x + 172)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 172)..(x + 176)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		architecture_specific_data: struct
			{
				u32(exe_contents[(x + 176)..(x + 180)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 180)..(x + 184)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		rva_of_global_pointer:      struct
			{
				u32(exe_contents[(x + 184)..(x + 188)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 188)..(x + 192)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		tls_table:                  struct
			{
				u32(exe_contents[(x + 192)..(x + 196)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 196)..(x + 200)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		load_config_table:          struct
			{
				u32(exe_contents[(x + 200)..(x + 204)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 204)..(x + 208)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		bound_import_table:         struct
			{
				u32(exe_contents[(x + 208)..(x + 212)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 212)..(x + 216)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		import_address_table:       struct
			{
				u32(exe_contents[(x + 216)..(x + 220)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 220)..(x + 224)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		delay_import_descriptor:    struct
			{
				u32(exe_contents[(x + 224)..(x + 228)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 228)..(x + 232)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		clr_runtime_header:         struct
			{
				u32(exe_contents[(x + 232)..(x + 236)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 236)..(x + 240)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		reserved:                   struct
			{
				u32(exe_contents[(x + 240)..(x + 244)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(x + 244)..(x + 248)].bytes().hex().parse_uint(16, 0) or { panic })
			}
	}

	exe_sections_count := int(pe32_file_header.sections_count)
	pe32_section_headers := []PE32_SECTION_HEADER{len: exe_sections_count, cap: exe_sections_count, init: PE32_SECTION_HEADER
		{
			name:                   [
			                        u8(exe_contents[(x + 40 * it + 248)..(x + 40 * it + 249)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(x + 40 * it + 249)..(x + 40 * it + 250)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(x + 40 * it + 250)..(x + 40 * it + 251)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(x + 40 * it + 251)..(x + 40 * it + 252)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(x + 40 * it + 252)..(x + 40 * it + 253)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(x + 40 * it + 253)..(x + 40 * it + 254)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(x + 40 * it + 254)..(x + 40 * it + 255)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(x + 40 * it + 255)..(x + 40 * it + 256)].bytes().hex().parse_uint(16, 0) or { panic })
			                        ]!
			virtual_size:           u32(exe_contents[(x + 40 * it + 256)..(x + 40 * it + 260)].bytes().hex().parse_uint(16, 0) or { panic })
			virtual_address:        u32(exe_contents[(x + 40 * it + 260)..(x + 40 * it + 264)].bytes().hex().parse_uint(16, 0) or { panic })
			sizeof_raw_data:        u32(exe_contents[(x + 40 * it + 264)..(x + 40 * it + 268)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_raw_data:        u32(exe_contents[(x + 40 * it + 268)..(x + 40 * it + 272)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_relocations:     u32(exe_contents[(x + 40 * it + 272)..(x + 40 * it + 276)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_line_numbers:    u32(exe_contents[(x + 40 * it + 276)..(x + 40 * it + 280)].bytes().hex().parse_uint(16, 0) or { panic })
			number_of_relocations:  u16(exe_contents[(x + 40 * it + 280)..(x + 40 * it + 282)].bytes().hex().parse_uint(16, 0) or { panic })
			number_of_line_numbers: u16(exe_contents[(x + 40 * it + 282)..(x + 40 * it + 284)].bytes().hex().parse_uint(16, 0) or { panic })
			characteristics:        u32(exe_contents[(x + 40 * it + 284)..(x + 40 * it + 288)].bytes().hex().parse_uint(16, 0) or { panic })
		}
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
	if pe32_file_header.characteristics & u16(0x02) != 0
	{
		println_debug("The EXE image is executable!")
	}
	else
	{
		println_error("The EXE image is not executable!")
		vin32_exit(1)
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

	// TODO: Running code goes here!

	return 0
}
