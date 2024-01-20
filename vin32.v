module main

import os

fn main()
{
	println_debug(os.args.str())

	if os.args.len != 2
	{
		println_error("Wrong command-line usage!")
		println("Usage: vin32.exe <your executable file>")
	}
	else
	{
		println_information("Running Vin32...")

		exe_path := os.args[1]
		exe_filename := os.file_name(exe_path)
		exe_contents := os.read_file(exe_path) or {
			println_error("The contents of the exe couldn't read!")
			vin32_exit(exit_failure)
			return
		}

		println_debug("Running ${exe_filename}...")

		exe_result := run_exe(exe_contents)
		println_information("${exe_filename} returns ${exe_result} value!")

		vin32_exit(exit_success)
	}
}
