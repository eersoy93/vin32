module main

import term

fn println_debug(msg string)
{
	$if debug
	{
		eprintln(term.bright_magenta("DEBUG:") + " $msg")
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

fn vin32_exit(exitcode int)
{
	println("Exiting with ${exitcode} code...")
	exit(exitcode)
}
