module main

import term

const panic_text = "Invalid unsigned integer parsing!"

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
