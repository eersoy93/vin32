module main

import encoding.binary
import term

const exit_success = 0
const exit_failure = 1

fn print_imports(pe32_import_descriptors []PE32_IMPORT_DESCRIPTOR, exe_memory []u8, pe32_optional_header PE32_OPTIONAL_HEADER)
{
	for pe32_import_descriptor in pe32_import_descriptors
	{
		mut dll_name_len := u8(0)
		for j in exe_memory[(pe32_import_descriptor.rva_of_name)..(pe32_import_descriptor.rva_of_name + 255)]
		{
			if j == u8(0)
			{
				break
			}
			dll_name_len++
		}
		println_debug("DLL is required for the APIs below: ${exe_memory[(pe32_import_descriptor.rva_of_name)..(pe32_import_descriptor.rva_of_name + dll_name_len)].bytestr()}")

		for j in 0..4096
		{
			import_address := binary.little_endian_u32(exe_memory[(pe32_import_descriptor.first_thunk + 4 * j)..(pe32_import_descriptor.first_thunk + 4 * j + 4)])
			if import_address == 0
			{
				break
			}
			import_name_address_start := import_address + 2
			mut import_name_address_end := import_name_address_start
			if import_name_address_start > pe32_optional_header.size_of_image
			{
				continue
			}
			for _ in 0..255
			{
				if exe_memory[import_name_address_end] == 0
				{
					break
				}
				import_name_address_end++
			}
			println_debug("    ${exe_memory[import_name_address_start..import_name_address_end].bytestr()}")
		}
	}
}

fn println_debug(msg string)
{
	$if debug
	{
		eprintln(term.bright_cyan("DEBUG:") + " $msg")
	}
	$else
	{
		return
	}
}

fn println_error(msg string)
{
	eprintln(term.bright_red("ERROR:") + " $msg")
}

fn println_information(msg string)
{
	println(term.bright_green("INFO:") + " $msg")
}

fn println_warning(msg string)
{
	eprintln(term.bright_yellow("WARNING:") + " $msg")
}

fn vin32_exit(exitcode int)
{
	println_information("Exiting with ${exitcode} code...")
	exit(exitcode)
}
