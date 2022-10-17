module main

fn println_debug(msg string)
{
	$if debug
	{
		println("DEBUG: $msg")
	}
	$else
	{
		return
	}
}

fn println_error(msg string)
{
	eprintln("ERROR: $msg")
}
