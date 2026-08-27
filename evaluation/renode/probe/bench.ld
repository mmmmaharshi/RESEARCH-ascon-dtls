ENTRY(reset_handler)
/* Unified HAL: heap/stack addrs canonical in evaluation/common/hal.h (HAL_HEAP_LIMIT/HAL_STACK_TOP) */

MEMORY
{
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
        *(.glue_7*)
        *(.glue_7t*)
    } > FLASH

    .data :
    {
        . = ALIGN(4);
        __data_start = .;
        *(.data*)
        __data_end = .;
    } > RAM AT> FLASH
    __data_load = LOADADDR(.data);

    .bss :
    {
        . = ALIGN(4);
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    . = ALIGN(4);
    __heap_start = .;
    __heap_end = 0x20008000; /* HAL_HEAP_LIMIT */
    end = __heap_start;
    __end__ = __heap_start;
    __stack_top = 0x2000C000; /* HAL_STACK_TOP */
}
