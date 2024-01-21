module main

import encoding.binary

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string) (PE32_DOS_HEADER, PE32_FILE_HEADER, PE32_OPTIONAL_HEADER, []PE32_SECTION_HEADER, u32, int)
{
	exe_contents_bytes := exe_contents.bytes()
	pe32_dos_header := PE32_DOS_HEADER
	{
		magic_number:                   binary.little_endian_u16(exe_contents_bytes[0..2])
		last_page_of_file_bytes:        binary.little_endian_u16(exe_contents_bytes[2..4])
		pages_in_file:                  binary.little_endian_u16(exe_contents_bytes[4..6])
		relocations:                    binary.little_endian_u16(exe_contents_bytes[6..8])
		size_of_header_in_paragraphs:   binary.little_endian_u16(exe_contents_bytes[8..10])
		extra_paragraphs_needed_min:    binary.little_endian_u16(exe_contents_bytes[10..12])
		extra_paragraphs_needed_max:    binary.little_endian_u16(exe_contents_bytes[12..14])
		initial_relative_ss_value:      binary.little_endian_u16(exe_contents_bytes[14..16])
		initial_sp_value:               binary.little_endian_u16(exe_contents_bytes[16..18])
		checksum:                       binary.little_endian_u16(exe_contents_bytes[18..20])
		initial_ip_value:               binary.little_endian_u16(exe_contents_bytes[20..22])
		initial_relative_cs_value:      binary.little_endian_u16(exe_contents_bytes[22..24])
		relocation_table_file_address:  binary.little_endian_u16(exe_contents_bytes[24..26])
		overlay_number:                 binary.little_endian_u16(exe_contents_bytes[26..28])
		reserved_words:                 [
		                                binary.little_endian_u16(exe_contents_bytes[28..30]),
		                                binary.little_endian_u16(exe_contents_bytes[30..32]),
		                                binary.little_endian_u16(exe_contents_bytes[32..34]),
		                                binary.little_endian_u16(exe_contents_bytes[34..36]),
		                                ]!
		oem_identifier:                 binary.little_endian_u16(exe_contents_bytes[36..38])
		oem_information:                binary.little_endian_u16(exe_contents_bytes[38..40])
		reserved_words_2:               [
		                                binary.little_endian_u16(exe_contents_bytes[40..42]),
		                                binary.little_endian_u16(exe_contents_bytes[42..44]),
		                                binary.little_endian_u16(exe_contents_bytes[44..46]),
		                                binary.little_endian_u16(exe_contents_bytes[46..48]),
		                                binary.little_endian_u16(exe_contents_bytes[48..50]),
		                                binary.little_endian_u16(exe_contents_bytes[50..52]),
		                                binary.little_endian_u16(exe_contents_bytes[52..54]),
		                                binary.little_endian_u16(exe_contents_bytes[54..56]),
		                                binary.little_endian_u16(exe_contents_bytes[56..58]),
		                                binary.little_endian_u16(exe_contents_bytes[58..60]),
		                                ]!
		pointer_to_pe_header:           binary.little_endian_u32(exe_contents_bytes[60..64])
	}

	pe_header_pointer := pe32_dos_header.pointer_to_pe_header

	pe32_file_header := PE32_FILE_HEADER
	{
		nt_signature:            binary.big_endian_u32(exe_contents_bytes[(pe_header_pointer)..(pe_header_pointer + 4)])
		machine_type:            binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 4)..(pe_header_pointer + 6)])
		sections_count:          binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 6)..(pe_header_pointer + 8)])
		time_date_stamp:         binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 8)..(pe_header_pointer + 12)])
		symbol_table_pointer:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 12)..(pe_header_pointer + 16)])
		number_of_symbols:       binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 16)..(pe_header_pointer + 20)])
		optional_header_size:    binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 20)..(pe_header_pointer + 22)])
		characteristics:         binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 22)..(pe_header_pointer + 24)])
	}

	pe32_optional_header := PE32_OPTIONAL_HEADER
	{
		magic:                      binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 24)..(pe_header_pointer + 26)])
		linker_version_major:       exe_contents_bytes[(pe_header_pointer + 26)..(pe_header_pointer + 27)][0]
		linker_version_minor:       exe_contents_bytes[(pe_header_pointer + 27)..(pe_header_pointer + 28)][0]
		code_size:                  binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 28)..(pe_header_pointer + 32)])
		initialized_data_size:      binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 32)..(pe_header_pointer + 36)])
		uninitialized_data_size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 36)..(pe_header_pointer + 40)])
		entry_point:                binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 40)..(pe_header_pointer + 44)])
		base_of_code:               binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 44)..(pe_header_pointer + 48)])
		base_of_data:               binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 48)..(pe_header_pointer + 52)])
		image_base:                 binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 52)..(pe_header_pointer + 56)])
		section_alignment:          binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 56)..(pe_header_pointer + 60)])
		file_alignment:             binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 60)..(pe_header_pointer + 64)])
		os_version_major:           binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 64)..(pe_header_pointer + 66)])
		os_version_minor:           binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 66)..(pe_header_pointer + 68)])
		image_version_major:        binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 68)..(pe_header_pointer + 70)])
		image_version_minor:        binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 70)..(pe_header_pointer + 72)])
		subsystem_version_major:    binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 72)..(pe_header_pointer + 74)])
		subsystem_version_minor:    binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 74)..(pe_header_pointer + 76)])
		win32_version_value:        binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 76)..(pe_header_pointer + 80)])
		size_of_image:              binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 80)..(pe_header_pointer + 84)])
		size_of_headers:            binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 84)..(pe_header_pointer + 88)])
		checksum:                   binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 88)..(pe_header_pointer + 92)])
		subsystem:                  binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 92)..(pe_header_pointer + 94)])
		dll_characteristics:        binary.little_endian_u16(exe_contents_bytes[(pe_header_pointer + 94)..(pe_header_pointer + 96)])
		size_of_stack_reserve:      binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 96)..(pe_header_pointer + 100)])
		size_of_stack_commit:       binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 100)..(pe_header_pointer + 104)])
		size_of_heap_reserve:       binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 104)..(pe_header_pointer + 108)])
		size_of_heap_commit:        binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 108)..(pe_header_pointer + 112)])
		loader_flags:               binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 112)..(pe_header_pointer + 116)])
		rvas_and_sizes_number:      binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 116)..(pe_header_pointer + 120)])
		export_table:               struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 120)..(pe_header_pointer + 124)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 124)..(pe_header_pointer + 128)])
			}
		import_table:               struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 128)..(pe_header_pointer + 132)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 132)..(pe_header_pointer + 136)])
			}
		resource_table:             struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 136)..(pe_header_pointer + 140)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 140)..(pe_header_pointer + 144)])
			}
		exception_table:            struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 144)..(pe_header_pointer + 148)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 148)..(pe_header_pointer + 152)])
			}
		certificate_table:          struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 152)..(pe_header_pointer + 156)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 156)..(pe_header_pointer + 160)])
			}
		base_relocation_table:      struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 160)..(pe_header_pointer + 164)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 164)..(pe_header_pointer + 168)])
			}
		debug_table:                struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 168)..(pe_header_pointer + 172)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 172)..(pe_header_pointer + 176)])
			}
		architecture_specific_data: struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 176)..(pe_header_pointer + 180)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 180)..(pe_header_pointer + 184)])
			}
		rva_of_global_pointer:      struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 184)..(pe_header_pointer + 188)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 188)..(pe_header_pointer + 192)])
			}
		tls_table:                  struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 192)..(pe_header_pointer + 196)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 196)..(pe_header_pointer + 200)])
			}
		load_config_table:          struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 200)..(pe_header_pointer + 204)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 204)..(pe_header_pointer + 208)])
			}
		bound_import_table:         struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 208)..(pe_header_pointer + 212)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 212)..(pe_header_pointer + 216)])
			}
		import_address_table:       struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 216)..(pe_header_pointer + 220)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 220)..(pe_header_pointer + 224)])
			}
		delay_import_descriptor:    struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 224)..(pe_header_pointer + 228)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 228)..(pe_header_pointer + 232)])
			}
		clr_runtime_header:         struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 232)..(pe_header_pointer + 236)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 236)..(pe_header_pointer + 240)])
			}
		reserved:                   struct
			{
				address: binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 240)..(pe_header_pointer + 244)])
				size:    binary.little_endian_u32(exe_contents_bytes[(pe_header_pointer + 244)..(pe_header_pointer + 248)])
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
