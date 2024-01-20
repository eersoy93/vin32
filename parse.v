module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string) (PE32_DOS_HEADER, PE32_FILE_HEADER, PE32_OPTIONAL_HEADER, []PE32_SECTION_HEADER, u16, int)
{
	pe32_dos_header := PE32_DOS_HEADER
	{
		magic_number:                   u16(exe_contents[0..2].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		last_page_of_file_bytes:        u16(exe_contents[2..4].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		pages_in_file:                  u16(exe_contents[4..6].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		relocations:                    u16(exe_contents[6..8].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_header_in_paragraphs:   u16(exe_contents[8..10].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		extra_paragraphs_needed_min:    u16(exe_contents[10..12].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		extra_paragraphs_needed_max:    u16(exe_contents[12..14].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		initial_relative_ss_value:      u16(exe_contents[14..16].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		initial_sp_value:               u16(exe_contents[16..18].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		checksum:                       u16(exe_contents[18..20].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		initial_ip_value:               u16(exe_contents[20..22].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		initial_relative_cs_value:      u16(exe_contents[22..24].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		relocation_table_file_address:  u16(exe_contents[24..26].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		overlay_number:                 u16(exe_contents[26..28].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		reserved_words:                 [
		                                u16(exe_contents[28..30].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[30..32].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[32..34].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[34..36].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		                                ]!
		oem_identifier:                 u16(exe_contents[36..38].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		oem_information:                u16(exe_contents[38..40].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		reserved_words_2:               [
		                                u16(exe_contents[40..42].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[42..44].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[44..46].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[46..48].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[48..50].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[50..52].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[52..54].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[54..56].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[56..58].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) }),
		                                u16(exe_contents[58..60].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		                                ]!
		pointer_to_pe_header:           u16(exe_contents[60..64].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
	}

	pe_header_pointer := pe32_dos_header.pointer_to_pe_header

	pe32_file_header := PE32_FILE_HEADER
	{
		nt_signature:            u32(exe_contents[pe_header_pointer..(pe_header_pointer + 4)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) })
		machine_type:            u16(exe_contents[(pe_header_pointer + 4)..(pe_header_pointer + 6)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		sections_count:          u16(exe_contents[(pe_header_pointer + 6)..(pe_header_pointer + 8)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		time_date_stamp:         u32(exe_contents[(pe_header_pointer + 8)..(pe_header_pointer + 12)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		symbol_table_pointer:    u32(exe_contents[(pe_header_pointer + 12)..(pe_header_pointer + 16)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		number_of_symbols:       u32(exe_contents[(pe_header_pointer + 16)..(pe_header_pointer + 20)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		optional_header_size:    u16(exe_contents[(pe_header_pointer + 20)..(pe_header_pointer + 22)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		characteristics:         u16(exe_contents[(pe_header_pointer + 22)..(pe_header_pointer + 24)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
	}

	pe32_optional_header := PE32_OPTIONAL_HEADER
	{
		magic:                      u16(exe_contents[(pe_header_pointer + 24)..(pe_header_pointer + 26)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		linker_version_major:       u8(exe_contents[(pe_header_pointer + 26)..(pe_header_pointer + 27)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) })
		linker_version_minor:       u8(exe_contents[(pe_header_pointer + 27)..(pe_header_pointer + 28)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) })
		code_size:                  u32(exe_contents[(pe_header_pointer + 28)..(pe_header_pointer + 32)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		initialized_data_size:      u32(exe_contents[(pe_header_pointer + 32)..(pe_header_pointer + 36)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		uninitialized_data_size:    u32(exe_contents[(pe_header_pointer + 36)..(pe_header_pointer + 40)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		entry_point:                u32(exe_contents[(pe_header_pointer + 40)..(pe_header_pointer + 44)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		base_of_code:               u32(exe_contents[(pe_header_pointer + 44)..(pe_header_pointer + 48)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		base_of_data:               u32(exe_contents[(pe_header_pointer + 48)..(pe_header_pointer + 52)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		image_base:                 u32(exe_contents[(pe_header_pointer + 52)..(pe_header_pointer + 56)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		section_alignment:          u32(exe_contents[(pe_header_pointer + 56)..(pe_header_pointer + 60)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		file_alignment:             u32(exe_contents[(pe_header_pointer + 60)..(pe_header_pointer + 64)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		os_version_major:           u16(exe_contents[(pe_header_pointer + 64)..(pe_header_pointer + 66)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		os_version_minor:           u16(exe_contents[(pe_header_pointer + 66)..(pe_header_pointer + 68)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		image_version_major:        u16(exe_contents[(pe_header_pointer + 68)..(pe_header_pointer + 70)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		image_version_minor:        u16(exe_contents[(pe_header_pointer + 70)..(pe_header_pointer + 72)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		subsystem_version_major:    u16(exe_contents[(pe_header_pointer + 72)..(pe_header_pointer + 74)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		subsystem_version_minor:    u16(exe_contents[(pe_header_pointer + 74)..(pe_header_pointer + 76)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		win32_version_value:        u32(exe_contents[(pe_header_pointer + 76)..(pe_header_pointer + 80)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_image:              u32(exe_contents[(pe_header_pointer + 80)..(pe_header_pointer + 84)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_headers:            u32(exe_contents[(pe_header_pointer + 84)..(pe_header_pointer + 88)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		checksum:                   u32(exe_contents[(pe_header_pointer + 88)..(pe_header_pointer + 92)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		subsystem:                  u16(exe_contents[(pe_header_pointer + 92)..(pe_header_pointer + 94)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		dll_characteristics:        u16(exe_contents[(pe_header_pointer + 94)..(pe_header_pointer + 96)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_stack_reserve:      u32(exe_contents[(pe_header_pointer + 96)..(pe_header_pointer + 100)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_stack_commit:       u32(exe_contents[(pe_header_pointer + 100)..(pe_header_pointer + 104)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_heap_reserve:       u32(exe_contents[(pe_header_pointer + 104)..(pe_header_pointer + 108)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		size_of_heap_commit:        u32(exe_contents[(pe_header_pointer + 108)..(pe_header_pointer + 112)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		loader_flags:               u32(exe_contents[(pe_header_pointer + 112)..(pe_header_pointer + 116)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		rvas_and_sizes_number:      u32(exe_contents[(pe_header_pointer + 116)..(pe_header_pointer + 120)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		export_table:               struct
			{
				address: u32(exe_contents[(pe_header_pointer + 120)..(pe_header_pointer + 124)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 124)..(pe_header_pointer + 128)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		import_table:               struct
			{
				address: u32(exe_contents[(pe_header_pointer + 128)..(pe_header_pointer + 132)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 132)..(pe_header_pointer + 136)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		resource_table:             struct
			{
				address: u32(exe_contents[(pe_header_pointer + 136)..(pe_header_pointer + 140)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 140)..(pe_header_pointer + 144)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		exception_table:            struct
			{
				address: u32(exe_contents[(pe_header_pointer + 144)..(pe_header_pointer + 148)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 148)..(pe_header_pointer + 152)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		certificate_table:          struct
			{
				address: u32(exe_contents[(pe_header_pointer + 152)..(pe_header_pointer + 156)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 156)..(pe_header_pointer + 160)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		base_relocation_table:      struct
			{
				address: u32(exe_contents[(pe_header_pointer + 160)..(pe_header_pointer + 164)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 164)..(pe_header_pointer + 168)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		debug_table:                struct
			{
				address: u32(exe_contents[(pe_header_pointer + 168)..(pe_header_pointer + 172)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 172)..(pe_header_pointer + 176)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		architecture_specific_data: struct
			{
				address: u32(exe_contents[(pe_header_pointer + 176)..(pe_header_pointer + 180)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 180)..(pe_header_pointer + 184)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		rva_of_global_pointer:      struct
			{
				address: u32(exe_contents[(pe_header_pointer + 184)..(pe_header_pointer + 188)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 188)..(pe_header_pointer + 192)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		tls_table:                  struct
			{
				address: u32(exe_contents[(pe_header_pointer + 192)..(pe_header_pointer + 196)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 196)..(pe_header_pointer + 200)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		load_config_table:          struct
			{
				address: u32(exe_contents[(pe_header_pointer + 200)..(pe_header_pointer + 204)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 204)..(pe_header_pointer + 208)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		bound_import_table:         struct
			{
				address: u32(exe_contents[(pe_header_pointer + 208)..(pe_header_pointer + 212)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 212)..(pe_header_pointer + 216)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		import_address_table:       struct
			{
				address: u32(exe_contents[(pe_header_pointer + 216)..(pe_header_pointer + 220)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 220)..(pe_header_pointer + 224)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		delay_import_descriptor:    struct
			{
				address: u32(exe_contents[(pe_header_pointer + 224)..(pe_header_pointer + 228)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 228)..(pe_header_pointer + 232)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		clr_runtime_header:         struct
			{
				address: u32(exe_contents[(pe_header_pointer + 232)..(pe_header_pointer + 236)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 236)..(pe_header_pointer + 240)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		reserved:                   struct
			{
				address: u32(exe_contents[(pe_header_pointer + 240)..(pe_header_pointer + 244)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				size:    u32(exe_contents[(pe_header_pointer + 244)..(pe_header_pointer + 248)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
	}

	exe_sections_count := int(pe32_file_header.sections_count)
	pe32_section_headers := []PE32_SECTION_HEADER
	{ len: exe_sections_count, cap: exe_sections_count, init: PE32_SECTION_HEADER
		{
			name:                   [
			                        u8(exe_contents[(pe_header_pointer + 40 * index + 248)..(pe_header_pointer + 40 * index + 249)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
			                        u8(exe_contents[(pe_header_pointer + 40 * index + 249)..(pe_header_pointer + 40 * index + 250)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
									u8(exe_contents[(pe_header_pointer + 40 * index + 250)..(pe_header_pointer + 40 * index + 251)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
			                        u8(exe_contents[(pe_header_pointer + 40 * index + 251)..(pe_header_pointer + 40 * index + 252)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
									u8(exe_contents[(pe_header_pointer + 40 * index + 252)..(pe_header_pointer + 40 * index + 253)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
			                        u8(exe_contents[(pe_header_pointer + 40 * index + 253)..(pe_header_pointer + 40 * index + 254)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
									u8(exe_contents[(pe_header_pointer + 40 * index + 254)..(pe_header_pointer + 40 * index + 255)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) }),
			                        u8(exe_contents[(pe_header_pointer + 40 * index + 255)..(pe_header_pointer + 40 * index + 256)].bytes().hex().parse_uint(16, 0) or { panic(panic_text) })
			                        ]!
			virtual_size:           u32(exe_contents[(pe_header_pointer + 40 * index + 256)..(pe_header_pointer + 40 * index + 260)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			virtual_address:        u32(exe_contents[(pe_header_pointer + 40 * index + 260)..(pe_header_pointer + 40 * index + 264)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			sizeof_raw_data:        u32(exe_contents[(pe_header_pointer + 40 * index + 264)..(pe_header_pointer + 40 * index + 268)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			ptr_to_raw_data:        u32(exe_contents[(pe_header_pointer + 40 * index + 268)..(pe_header_pointer + 40 * index + 272)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			ptr_to_relocations:     u32(exe_contents[(pe_header_pointer + 40 * index + 272)..(pe_header_pointer + 40 * index + 276)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			ptr_to_line_numbers:    u32(exe_contents[(pe_header_pointer + 40 * index + 276)..(pe_header_pointer + 40 * index + 280)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			number_of_relocations:  u16(exe_contents[(pe_header_pointer + 40 * index + 280)..(pe_header_pointer + 40 * index + 282)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			number_of_line_numbers: u16(exe_contents[(pe_header_pointer + 40 * index + 282)..(pe_header_pointer + 40 * index + 284)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			characteristics:        u32(exe_contents[(pe_header_pointer + 40 * index + 284)..(pe_header_pointer + 40 * index + 288)].bytes().reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
		}
	}

	return pe32_dos_header, pe32_file_header, pe32_optional_header, pe32_section_headers, pe_header_pointer, exe_sections_count
}

fn parse_imports(exe_memory  []u8, import_directories_address int, mut pe32_import_descriptors []PE32_IMPORT_DESCRIPTOR)
{
	for i in 0..(max_int)
	{
		pe32_import_descriptor := PE32_IMPORT_DESCRIPTOR
			{
				original_first_thunk: u32(exe_memory[(import_directories_address + i * 20)..(import_directories_address + i * 20 + 4)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				time_date_stamp:      u32(exe_memory[(import_directories_address + i * 20 + 4)..(import_directories_address + i * 20 + 8)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				forwarder:            u32(exe_memory[(import_directories_address + i * 20 + 8)..(import_directories_address + i * 20 + 12)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				rva_of_name:          u32(exe_memory[(import_directories_address + i * 20 + 12)..(import_directories_address + i * 20 + 16)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
				first_thunk:          u32(exe_memory[(import_directories_address + i * 20 + 16)..(import_directories_address + i * 20 + 20)].reverse().hex().parse_uint(16, 0) or { panic(panic_text) })
			}
		if pe32_import_descriptor.original_first_thunk == u32(0x00000000)
		{
			break
		}
		else
		{
			pe32_import_descriptors << pe32_import_descriptor
		}
	}
}
