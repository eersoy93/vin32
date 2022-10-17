module main

import os

fn main()
{
	println_debug(os.args.str())

	if os.args.len != 2
	{
		println("Usage: vin32.exe <your executable file>")
	}
	else
	{
		println("Running Vin32...")  // Under construction!!!

		exe_path := os.args[0]
		exe_contents := os.read_file(exe_path) or {
			println_error("The contents of the exe couldn't read!")
			exit(1)
		}

		if exe_contents[0..2] == "MZ"
		{
			println_debug("MZ signature found!")
		}
		else
		{
			println_debug("MZ signature not found!")
		}
	}
}
