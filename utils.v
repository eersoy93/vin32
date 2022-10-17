module main

fn println_debug(msg string)
{
	$if debug
	{
		eprintln("DEBUG: $msg")
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

fn vin32_exit(exitcode int)
{
	println("Exiting with ${exitcode} code...")
	exit(exitcode)
}
