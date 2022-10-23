module main

// For 32-bit PE exe files only currently
fn parse_exe(exe_contents string)
{
	// Classify EXE contents to PE32 struct
	pe32 := PE32
	{
		pe32_dos_header: struct
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
		pe32_file_header: struct
		{
			machine_type:               u16(exe_contents[220..222].bytes().reverse().hex().parse_uint(16, 0) or { return })
			sections_count:             u16(exe_contents[222..224].bytes().reverse().hex().parse_uint(16, 0) or { return })
			time_date_stamp:            u32(exe_contents[224..228].bytes().reverse().hex().parse_uint(16, 0) or { return })
			symbol_table_pointer:       u32(exe_contents[228..232].bytes().reverse().hex().parse_uint(16, 0) or { return })
			number_of_symbols:          u32(exe_contents[232..236].bytes().reverse().hex().parse_uint(16, 0) or { return })
			optional_header_size:       u16(exe_contents[236..238].bytes().reverse().hex().parse_uint(16, 0) or { return })
			characteristics:            u16(exe_contents[238..240].bytes().reverse().hex().parse_uint(16, 0) or { return })
		}
		pe32_optional_header: struct
		{
			magic:                      u16(exe_contents[240..242].bytes().reverse().hex().parse_uint(16, 0) or { return })
			linker_version_major:       u8(exe_contents[242].bytes().reverse().hex().parse_uint(16, 0) or { return })
			linker_version_minor:       u8(exe_contents[243].bytes().reverse().hex().parse_uint(16, 0) or { return })
			code_size:                  u32(exe_contents[244..248].bytes().reverse().hex().parse_uint(16, 0) or { return })
			initialized_data_size:      u32(exe_contents[248..252].bytes().reverse().hex().parse_uint(16, 0) or { return })
			uninitialized_data_size:    u32(exe_contents[252..256].bytes().reverse().hex().parse_uint(16, 0) or { return })
			entry_point:                u32(exe_contents[256..260].bytes().reverse().hex().parse_uint(16, 0) or { return })
			base_of_code:               u32(exe_contents[260..264].bytes().reverse().hex().parse_uint(16, 0) or { return })
			base_of_data:               u32(exe_contents[264..268].bytes().reverse().hex().parse_uint(16, 0) or { return })
			image_size:                 u32(exe_contents[268..272].bytes().reverse().hex().parse_uint(16, 0) or { return })
			section_alignment:          u32(exe_contents[272..276].bytes().reverse().hex().parse_uint(16, 0) or { return })
			file_alignment:             u32(exe_contents[276..280].bytes().reverse().hex().parse_uint(16, 0) or { return })
			os_version_major:           u16(exe_contents[280..282].bytes().reverse().hex().parse_uint(16, 0) or { return })
			os_version_minor:           u16(exe_contents[282..284].bytes().reverse().hex().parse_uint(16, 0) or { return })
			subsystem_version_major:    u16(exe_contents[284..286].bytes().reverse().hex().parse_uint(16, 0) or { return })
			subsystem_version_minor:    u16(exe_contents[286..288].bytes().reverse().hex().parse_uint(16, 0) or { return })
			win32_version_value:        u16(exe_contents[288..290].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_image:              u32(exe_contents[290..294].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_headers:            u32(exe_contents[294..298].bytes().reverse().hex().parse_uint(16, 0) or { return })
			checksum:                   u32(exe_contents[298..302].bytes().reverse().hex().parse_uint(16, 0) or { return })
			subsystem:                  u32(exe_contents[302..306].bytes().reverse().hex().parse_uint(16, 0) or { return })
			dll_characteristics:        u16(exe_contents[306..308].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_stack_reserve:      u32(exe_contents[308..312].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_stack_commit:       u32(exe_contents[312..316].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_heap_reserve:       u32(exe_contents[316..320].bytes().reverse().hex().parse_uint(16, 0) or { return })
			size_of_heap_commit:        u32(exe_contents[320..324].bytes().reverse().hex().parse_uint(16, 0) or { return })
			loader_flags:               u32(exe_contents[324..328].bytes().reverse().hex().parse_uint(16, 0) or { return })
			rvas_and_sizes_number:      u32(exe_contents[328..332].bytes().reverse().hex().parse_uint(16, 0) or { return })
			export_table:               u32(exe_contents[332..336].bytes().reverse().hex().parse_uint(16, 0) or { return })
			import_table:               u32(exe_contents[336..340].bytes().reverse().hex().parse_uint(16, 0) or { return })
			resource_table:             u32(exe_contents[340..344].bytes().reverse().hex().parse_uint(16, 0) or { return })
			exception_table:            u32(exe_contents[344..348].bytes().reverse().hex().parse_uint(16, 0) or { return })
			certificate_table:          u32(exe_contents[348..352].bytes().reverse().hex().parse_uint(16, 0) or { return })
			base_relocation_table:      u32(exe_contents[352..356].bytes().reverse().hex().parse_uint(16, 0) or { return })
			debug_table:                u32(exe_contents[356..360].bytes().reverse().hex().parse_uint(16, 0) or { return })
			architecture_specific_data: u32(exe_contents[360..364].bytes().reverse().hex().parse_uint(16, 0) or { return })
			rva_of_global_pointer:      u32(exe_contents[364..368].bytes().reverse().hex().parse_uint(16, 0) or { return })
			tls_table:                  u32(exe_contents[368..372].bytes().reverse().hex().parse_uint(16, 0) or { return })
			load_config_table:          u32(exe_contents[372..376].bytes().reverse().hex().parse_uint(16, 0) or { return })
			bound_import_table:         u32(exe_contents[376..380].bytes().reverse().hex().parse_uint(16, 0) or { return })
			import_address_table:       u32(exe_contents[380..384].bytes().reverse().hex().parse_uint(16, 0) or { return })
			delay_import_descriptor:    u32(exe_contents[384..388].bytes().reverse().hex().parse_uint(16, 0) or { return })
			clr_runtime_header:         u32(exe_contents[388..392].bytes().reverse().hex().parse_uint(16, 0) or { return })
		}
		section_header: struct
		{
			name:                   u64(exe_contents[392..400].bytes().reverse().hex().parse_uint(16, 0) or { return })
			virtual_size:           u32(exe_contents[400..404].bytes().reverse().hex().parse_uint(16, 0) or { return })
			virtual_address:        u32(exe_contents[404..408].bytes().reverse().hex().parse_uint(16, 0) or { return })
			sizeof_raw_data:        u32(exe_contents[408..412].bytes().reverse().hex().parse_uint(16, 0) or { return })
			ptr_to_raw_data:        u32(exe_contents[412..416].bytes().reverse().hex().parse_uint(16, 0) or { return })
			ptr_to_relocations:     u32(exe_contents[416..420].bytes().reverse().hex().parse_uint(16, 0) or { return })
			ptr_to_line_numbers:    u32(exe_contents[420..424].bytes().reverse().hex().parse_uint(16, 0) or { return })
			number_of_relocations:  u16(exe_contents[424..426].bytes().reverse().hex().parse_uint(16, 0) or { return })
			number_of_line_numbers: u16(exe_contents[426..428].bytes().reverse().hex().parse_uint(16, 0) or { return })
			characteristics:        u32(exe_contents[428..432].bytes().reverse().hex().parse_uint(16, 0) or { return })
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
