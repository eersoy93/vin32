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
	}
}
