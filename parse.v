module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string) (PE32_DOS_HEADER, PE32_FILE_HEADER, PE32_OPTIONAL_HEADER, []PE32_SECTION_HEADER, u16, int)
{
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

	pe_header_pointer := pe32_dos_header.pointer_to_pe_header

	pe32_file_header := PE32_FILE_HEADER
	{
		nt_signature:            u32(exe_contents[pe_header_pointer..(pe_header_pointer + 4)].bytes().hex().parse_uint(16, 0) or { panic })
		machine_type:            u16(exe_contents[(pe_header_pointer + 4)..(pe_header_pointer + 6)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		sections_count:          u16(exe_contents[(pe_header_pointer + 6)..(pe_header_pointer + 8)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		time_date_stamp:         u32(exe_contents[(pe_header_pointer + 8)..(pe_header_pointer + 12)].bytes().hex().parse_uint(16, 0) or { panic })
		symbol_table_pointer:    u32(exe_contents[(pe_header_pointer + 12)..(pe_header_pointer + 16)].bytes().hex().parse_uint(16, 0) or { panic })
		number_of_symbols:       u32(exe_contents[(pe_header_pointer + 16)..(pe_header_pointer + 20)].bytes().hex().parse_uint(16, 0) or { panic })
		optional_header_size:    u16(exe_contents[(pe_header_pointer + 20)..(pe_header_pointer + 22)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		characteristics:         u16(exe_contents[(pe_header_pointer + 22)..(pe_header_pointer + 24)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
	}

	pe32_optional_header := PE32_OPTIONAL_HEADER
	{
		magic:                      u16(exe_contents[(pe_header_pointer + 24)..(pe_header_pointer + 26)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		linker_version_major:       u8(exe_contents[(pe_header_pointer + 26)..(pe_header_pointer + 27)].bytes().hex().parse_uint(16, 0) or { panic })
		linker_version_minor:       u8(exe_contents[(pe_header_pointer + 27)..(pe_header_pointer + 28)].bytes().hex().parse_uint(16, 0) or { panic })
		code_size:                  u32(exe_contents[(pe_header_pointer + 28)..(pe_header_pointer + 32)].bytes().hex().parse_uint(16, 0) or { panic })
		initialized_data_size:      u32(exe_contents[(pe_header_pointer + 32)..(pe_header_pointer + 36)].bytes().hex().parse_uint(16, 0) or { panic })
		uninitialized_data_size:    u32(exe_contents[(pe_header_pointer + 36)..(pe_header_pointer + 40)].bytes().hex().parse_uint(16, 0) or { panic })
		entry_point:                u32(exe_contents[(pe_header_pointer + 40)..(pe_header_pointer + 44)].bytes().hex().parse_uint(16, 0) or { panic })
		base_of_code:               u32(exe_contents[(pe_header_pointer + 44)..(pe_header_pointer + 48)].bytes().hex().parse_uint(16, 0) or { panic })
		base_of_data:               u32(exe_contents[(pe_header_pointer + 48)..(pe_header_pointer + 52)].bytes().hex().parse_uint(16, 0) or { panic })
		image_base:                 u32(exe_contents[(pe_header_pointer + 52)..(pe_header_pointer + 56)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		section_alignment:          u32(exe_contents[(pe_header_pointer + 56)..(pe_header_pointer + 60)].bytes().hex().parse_uint(16, 0) or { panic })
		file_alignment:             u32(exe_contents[(pe_header_pointer + 60)..(pe_header_pointer + 64)].bytes().hex().parse_uint(16, 0) or { panic })
		os_version_major:           u16(exe_contents[(pe_header_pointer + 64)..(pe_header_pointer + 66)].bytes().hex().parse_uint(16, 0) or { panic })
		os_version_minor:           u16(exe_contents[(pe_header_pointer + 66)..(pe_header_pointer + 68)].bytes().hex().parse_uint(16, 0) or { panic })
		image_version_major:        u16(exe_contents[(pe_header_pointer + 68)..(pe_header_pointer + 70)].bytes().hex().parse_uint(16, 0) or { panic })
		image_version_minor:        u16(exe_contents[(pe_header_pointer + 70)..(pe_header_pointer + 72)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem_version_major:    u16(exe_contents[(pe_header_pointer + 72)..(pe_header_pointer + 74)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem_version_minor:    u16(exe_contents[(pe_header_pointer + 74)..(pe_header_pointer + 76)].bytes().hex().parse_uint(16, 0) or { panic })
		win32_version_value:        u32(exe_contents[(pe_header_pointer + 76)..(pe_header_pointer + 80)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_image:              u32(exe_contents[(pe_header_pointer + 80)..(pe_header_pointer + 84)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		size_of_headers:            u32(exe_contents[(pe_header_pointer + 84)..(pe_header_pointer + 88)].bytes().reverse().hex().parse_uint(16, 0) or { panic })
		checksum:                   u32(exe_contents[(pe_header_pointer + 88)..(pe_header_pointer + 92)].bytes().hex().parse_uint(16, 0) or { panic })
		subsystem:                  u16(exe_contents[(pe_header_pointer + 92)..(pe_header_pointer + 94)].bytes().hex().parse_uint(16, 0) or { panic })
		dll_characteristics:        u16(exe_contents[(pe_header_pointer + 94)..(pe_header_pointer + 96)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_stack_reserve:      u32(exe_contents[(pe_header_pointer + 96)..(pe_header_pointer + 100)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_stack_commit:       u32(exe_contents[(pe_header_pointer + 100)..(pe_header_pointer + 104)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_heap_reserve:       u32(exe_contents[(pe_header_pointer + 104)..(pe_header_pointer + 108)].bytes().hex().parse_uint(16, 0) or { panic })
		size_of_heap_commit:        u32(exe_contents[(pe_header_pointer + 108)..(pe_header_pointer + 112)].bytes().hex().parse_uint(16, 0) or { panic })
		loader_flags:               u32(exe_contents[(pe_header_pointer + 112)..(pe_header_pointer + 116)].bytes().hex().parse_uint(16, 0) or { panic })
		rvas_and_sizes_number:      u32(exe_contents[(pe_header_pointer + 116)..(pe_header_pointer + 120)].bytes().hex().parse_uint(16, 0) or { panic })
		export_table:               struct
			{
				u32(exe_contents[(pe_header_pointer + 120)..(pe_header_pointer + 124)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 124)..(pe_header_pointer + 128)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		import_table:               struct
			{
				u32(exe_contents[(pe_header_pointer + 128)..(pe_header_pointer + 132)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 132)..(pe_header_pointer + 136)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		resource_table:             struct
			{
				u32(exe_contents[(pe_header_pointer + 136)..(pe_header_pointer + 140)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 140)..(pe_header_pointer + 144)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		exception_table:            struct
			{
				u32(exe_contents[(pe_header_pointer + 144)..(pe_header_pointer + 148)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 148)..(pe_header_pointer + 152)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		certificate_table:          struct
			{
				u32(exe_contents[(pe_header_pointer + 152)..(pe_header_pointer + 156)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 156)..(pe_header_pointer + 160)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		base_relocation_table:      struct
			{
				u32(exe_contents[(pe_header_pointer + 160)..(pe_header_pointer + 164)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 164)..(pe_header_pointer + 168)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		debug_table:                struct
			{
				u32(exe_contents[(pe_header_pointer + 168)..(pe_header_pointer + 172)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 172)..(pe_header_pointer + 176)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		architecture_specific_data: struct
			{
				u32(exe_contents[(pe_header_pointer + 176)..(pe_header_pointer + 180)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 180)..(pe_header_pointer + 184)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		rva_of_global_pointer:      struct
			{
				u32(exe_contents[(pe_header_pointer + 184)..(pe_header_pointer + 188)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 188)..(pe_header_pointer + 192)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		tls_table:                  struct
			{
				u32(exe_contents[(pe_header_pointer + 192)..(pe_header_pointer + 196)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 196)..(pe_header_pointer + 200)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		load_config_table:          struct
			{
				u32(exe_contents[(pe_header_pointer + 200)..(pe_header_pointer + 204)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 204)..(pe_header_pointer + 208)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		bound_import_table:         struct
			{
				u32(exe_contents[(pe_header_pointer + 208)..(pe_header_pointer + 212)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 212)..(pe_header_pointer + 216)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		import_address_table:       struct
			{
				u32(exe_contents[(pe_header_pointer + 216)..(pe_header_pointer + 220)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 220)..(pe_header_pointer + 224)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		delay_import_descriptor:    struct
			{
				u32(exe_contents[(pe_header_pointer + 224)..(pe_header_pointer + 228)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 228)..(pe_header_pointer + 232)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		clr_runtime_header:         struct
			{
				u32(exe_contents[(pe_header_pointer + 232)..(pe_header_pointer + 236)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 236)..(pe_header_pointer + 240)].bytes().hex().parse_uint(16, 0) or { panic })
			}
		reserved:                   struct
			{
				u32(exe_contents[(pe_header_pointer + 240)..(pe_header_pointer + 244)].bytes().hex().parse_uint(16, 0) or { panic })
				u32(exe_contents[(pe_header_pointer + 244)..(pe_header_pointer + 248)].bytes().hex().parse_uint(16, 0) or { panic })
			}
	}

	exe_sections_count := int(pe32_file_header.sections_count)
	pe32_section_headers := []PE32_SECTION_HEADER{len: exe_sections_count, cap: exe_sections_count, init: PE32_SECTION_HEADER
		{
			name:                   [
			                        u8(exe_contents[(pe_header_pointer + 40 * it + 248)..(pe_header_pointer + 40 * it + 249)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(pe_header_pointer + 40 * it + 249)..(pe_header_pointer + 40 * it + 250)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(pe_header_pointer + 40 * it + 250)..(pe_header_pointer + 40 * it + 251)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(pe_header_pointer + 40 * it + 251)..(pe_header_pointer + 40 * it + 252)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(pe_header_pointer + 40 * it + 252)..(pe_header_pointer + 40 * it + 253)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(pe_header_pointer + 40 * it + 253)..(pe_header_pointer + 40 * it + 254)].bytes().hex().parse_uint(16, 0) or { panic }),
									u8(exe_contents[(pe_header_pointer + 40 * it + 254)..(pe_header_pointer + 40 * it + 255)].bytes().hex().parse_uint(16, 0) or { panic }),
			                        u8(exe_contents[(pe_header_pointer + 40 * it + 255)..(pe_header_pointer + 40 * it + 256)].bytes().hex().parse_uint(16, 0) or { panic })
			                        ]!
			virtual_size:           u32(exe_contents[(pe_header_pointer + 40 * it + 256)..(pe_header_pointer + 40 * it + 260)].bytes().hex().parse_uint(16, 0) or { panic })
			virtual_address:        u32(exe_contents[(pe_header_pointer + 40 * it + 260)..(pe_header_pointer + 40 * it + 264)].bytes().hex().parse_uint(16, 0) or { panic })
			sizeof_raw_data:        u32(exe_contents[(pe_header_pointer + 40 * it + 264)..(pe_header_pointer + 40 * it + 268)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_raw_data:        u32(exe_contents[(pe_header_pointer + 40 * it + 268)..(pe_header_pointer + 40 * it + 272)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_relocations:     u32(exe_contents[(pe_header_pointer + 40 * it + 272)..(pe_header_pointer + 40 * it + 276)].bytes().hex().parse_uint(16, 0) or { panic })
			ptr_to_line_numbers:    u32(exe_contents[(pe_header_pointer + 40 * it + 276)..(pe_header_pointer + 40 * it + 280)].bytes().hex().parse_uint(16, 0) or { panic })
			number_of_relocations:  u16(exe_contents[(pe_header_pointer + 40 * it + 280)..(pe_header_pointer + 40 * it + 282)].bytes().hex().parse_uint(16, 0) or { panic })
			number_of_line_numbers: u16(exe_contents[(pe_header_pointer + 40 * it + 282)..(pe_header_pointer + 40 * it + 284)].bytes().hex().parse_uint(16, 0) or { panic })
			characteristics:        u32(exe_contents[(pe_header_pointer + 40 * it + 284)..(pe_header_pointer + 40 * it + 288)].bytes().hex().parse_uint(16, 0) or { panic })
		}
	}

	return pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers, pe_header_pointer, exe_sections_count
}
