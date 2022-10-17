module main

import os

fn main()
{
	$if debug
	{
		println_debug(os.args.str())
	}

	if os.args.len != 2
	{
		println("Usage: vin32.exe <your executable file>")
	}
	else
	{
		println("Running Vin32...")  // Under construction!!!
		exe_path := os.args[0]
		exe_contents := os.read_file(exe_path) or {
			return
		}

		if exe_contents[0..2] == "MZ"
		{
			println("MZ signature found!!!")
		}
		else
		{
			println("MZ signature not found!!!")
		}
	}
}
