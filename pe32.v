module main

// PE32 structs and other data structures

const
(
	pe32_magic_number = 0x5A4D                             // "MZ"
	pe32_nt_signature = 0x50450000                         // "PE\0\0"
	pe32_machine_type_i386 = 0x14c                         // IMAGE_FILE_MACHINE_I386
	pe32_optional_magic = 0x010b                           // PE32 (NT32)
)

struct PE32_DOS_HEADER
{
	magic_number                     u16
	last_page_of_file_bytes          u16
	pages_in_file                    u16
	relocations                      u16
	size_of_header_in_paragraphs     u16
	extra_paragraphs_needed_min      u16
	extra_paragraphs_needed_max      u16
	initial_relative_ss_value        u16
	initial_sp_value                 u16
	checksum                         u16
	initial_ip_value                 u16
	initial_relative_cs_value        u16
	relocation_table_file_address    u16
	overlay_number                   u16
	reserved_words                [4]u16
	oem_identifier                   u16
	oem_information                  u16
	reserved_words_2             [10]u16
	pointer_to_pe_header             u16
}

struct PE32_FILE_HEADER
{
	nt_signature         u32
	machine_type         u16
	sections_count       u16
	time_date_stamp      u32
	symbol_table_pointer u32
	number_of_symbols    u32
	optional_header_size u16
	characteristics      u16
}

struct PE32_OPTIONAL_HEADER
{
	magic                      u16
	linker_version_major       u8
	linker_version_minor       u8
	code_size                  u32
	initialized_data_size      u32
	uninitialized_data_size    u32
	entry_point                u32
	base_of_code               u32
	base_of_data               u32
	image_base                 u32
	section_alignment          u32
	file_alignment             u32
	os_version_major           u16
	os_version_minor           u16
	image_version_major        u16
	image_version_minor        u16
	subsystem_version_major    u16
	subsystem_version_minor    u16
	win32_version_value        u32
	size_of_image              u32
	size_of_headers            u32
	checksum                   u32
	subsystem                  u16
	dll_characteristics        u16
	size_of_stack_reserve      u32
	size_of_stack_commit       u32
	size_of_heap_reserve       u32
	size_of_heap_commit        u32
	loader_flags               u32
	rvas_and_sizes_number      u32
	export_table               struct
	{
		address        u32
		size           u32
	}
	import_table               struct
	{
		address        u32
		size           u32
	}
	resource_table             struct
	{
		address        u32
		size           u32
	}
	exception_table            struct
	{
		address        u32
		size           u32
	}
	certificate_table          struct
	{
		address        u32
		size           u32
	}
	base_relocation_table      struct
	{
		address        u32
		size           u32
	}
	debug_table                struct
	{
		address        u32
		size           u32
	}
	architecture_specific_data struct
	{
		address        u32
		size           u32
	}
	rva_of_global_pointer      struct
	{
		address        u32
		size           u32
	}
	tls_table                  struct
	{
		address        u32
		size           u32
	}
	load_config_table          struct
	{
		address        u32
		size           u32
	}
	bound_import_table         struct
	{
		address        u32
		size           u32
	}
	import_address_table       struct
	{
		address        u32
		size           u32
	}
	delay_import_descriptor    struct
	{
		address        u32
		size           u32
	}
	clr_runtime_header         struct
	{
		address        u32
		size           u32
	}
	reserved                   struct
	{
		address        u32
		size           u32
	}
}

struct PE32_SECTION_HEADER
{
	name                   [8]u8
	virtual_size              u32
	virtual_address           u32
	sizeof_raw_data           u32
	ptr_to_raw_data           u32
	ptr_to_relocations        u32
	ptr_to_line_numbers       u32
	number_of_relocations     u16
	number_of_line_numbers    u16
	characteristics           u32
}

struct PE32_IMPORT_DESCRIPTOR
{
	original_first_thunk   u32
	time_date_stamp        u32
	forwarder              u32
	rva_of_name            u32
	first_thunk            u32
}
