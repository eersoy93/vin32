module main

fn parse_exe(exe_contents string)
{
	if exe_contents[0..2] == "MZ"
	{
		println_debug("MZ signature found!")
	}
	else
	{
		println_debug("MZ signature not found!")
	}
}
