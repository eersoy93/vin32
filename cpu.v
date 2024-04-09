module main

struct CpuRegs
{
	eax struct
	{
		eax_upper u16
		ah u8
		al u8
	}
	ebx struct
	{
		ebx_upper u16
		bh u8
		bl u8
	}
	ecx struct
	{
		ecx_upper u16
		ch u8
		cl u8
	}
	edx struct
	{
		edx_upper u16
		dh u8
		dl u8
	}
	ebp struct
	{
		ebp_upper u16
		bp u8
	}
	esp struct
	{
		esp_upper u16
		sp u8
	}
	esi struct
	{
		esi_upper u16
		si u8
	}
	edi struct
	{
		edi_upper u16
		di u8
	}
	cs u16
	ds u16
	es u16
	fs u16
	gs u16
	ss u16
	eflags struct
	{
		eflags_upper u16
		flags u16
	}
	eip struct
	{
		eip_upper u16
		ip u16
	}
}

fn init_cpu() &CpuRegs
{
	return &CpuRegs
	{
		eax: struct
		{
			eax_upper: 0
			ah: 0
			al: 0
		}
		ebx: struct
		{
			ebx_upper: 0
			bh: 0
			bl: 0
		}
		ecx: struct
		{
			ecx_upper: 0
			ch: 0
			cl: 0
		}
		edx: struct
		{
			edx_upper: 0
			dh: 0
			dl: 0
		}
		ebp: struct
		{
			ebp_upper: 0
			bp: 0
		}
		esp: struct
		{
			esp_upper: 0
			sp: 0
		}
		esi: struct
		{
			esi_upper: 0
			si: 0
		}
		edi: struct
		{
			edi_upper: 0
			di: 0
		}
		cs: 0
		ds: 0
		es: 0
		fs: 0
		gs: 0
		ss: 0
		eflags: struct
		{
			eflags_upper: 0
			flags: 0
		}
		eip: struct
		{
			eip_upper: 0
			ip: 0
		}
	}
}
