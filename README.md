# Vin32

Run your old Windows executables on modern systems. Will be written with V language. (under construction)

Inspired from [retrowin32](https://github.com/evmar/retrowin32).

## Status

Vin32 has parse some PE32 EXE opcodes, but it can't emulate them currently.

I use [7-Zip 9.20 EXE (32-bit)](https://www.7-zip.org/a/7z920.exe) for development testing.

## Running

You can test your exe directly:

```v run . <your_exe_filename_and_filepath>```

If you want to see debug messages when running:

```v -cg run . <your_exe_filename_and_filepath>```

Or run my tests:

```./tests.sh```

## Author

This software is written by Erdem Ersoy.

## Copyright and License

Copyright (c) 2022-2024 Erdem Ersoy (eersoy93)

Licensed with MIT license. See LICENSE for full license text.
