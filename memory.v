module main

// Initialize (define) EXE memory
fn define_memory(image_size u32) []u8
{
	return []u8{len: int(image_size), cap: int(image_size), init: 0}
}
