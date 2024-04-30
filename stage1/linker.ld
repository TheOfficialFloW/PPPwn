OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

PHDRS
{
	text PT_LOAD ;
	rodata PT_LOAD ;
	data PT_LOAD ;
	bss PT_LOAD ;
}

SECTIONS
{
	.text : { *(.text) } :text
	.rodata : { *(.rodata) *(.rodata.*) } :rodata
	.data : { *(.data) } :data
	.bss : { *(.bss) *(COMMON) } :bss
	.shstrtab : { *(.shstrtab) }
	/DISCARD/ : { *(*) }
}
