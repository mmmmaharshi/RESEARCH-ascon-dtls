.syntax unified
.thumb

.section .isr_vector,"a",%progbits
.word __stack_top
.word reset_handler
.word default_handler
.word default_handler
.word 0,0,0,0,0,0,0,0
.word 0,0,0,0,0,0,0,0

.section .text
.thumb_func
.global reset_handler
.type reset_handler, %function
reset_handler:
    /* copy .data from flash to ram */
    ldr r0, =__data_load
    ldr r1, =__data_start
    ldr r2, =__data_end
1:  cmp r1, r2
    bhs 2f
    ldr r3, [r0]
    adds r0, r0, #4
    str r3, [r1]
    adds r1, r1, #4
    b 1b
2:  /* zero .bss */
    ldr r1, =__bss_start
    ldr r2, =__bss_end
3:  cmp r1, r2
    bhs 4f
    movs r3, #0
    str r3, [r1]
    adds r1, r1, #4
    b 3b
4:  /* call main */
    bl main
5:  b 5b

.thumb_func
default_handler:
    b default_handler
