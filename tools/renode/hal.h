#ifndef RENODE_HAL_H
#define RENODE_HAL_H
#include <stdint.h>
/* hal.h — pqm4-style DWT cycle counter for Cortex-M3/M4/M33 (not M0+).
 * DEMCR@0xE000EDFC TRCENA, DWT_CTRL@0xE0001000 CYCCNTENA,
 * DWT_CYCCNT@0xE0001004. M0+ has no DWT — fallback to SysTick
 * SYST_CVR@0xE000E018 in bench_main.c / bench_record.c.
 * Enable with -DPQM4_DWT (build_bench.ps1 -Dwt, -O2 vs -Os).
 * Mirrors pqm4 hal.h; minimal ~30 LOC. */
#define DEMCR_ADDR      0xE000EDFCu
#define DWT_CTRL_ADDR   0xE0001000u
#define DWT_CYCCNT_ADDR 0xE0001004u
#define DEMCR      (*(volatile uint32_t*)DEMCR_ADDR)
#define DWT_CTRL   (*(volatile uint32_t*)DWT_CTRL_ADDR)
#define DWT_CYCCNT (*(volatile uint32_t*)DWT_CYCCNT_ADDR)
#define DEMCR_TRCENA       (1u << 24)
#define DWT_CTRL_CYCCNTENA (1u << 0)
static inline void hal_dwt_enable(void){
    DEMCR |= DEMCR_TRCENA;          /* enable trace */
    DWT_CYCCNT = 0;                  /* clear */
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;  /* enable counter */
}
static inline uint32_t hal_cc(void){
    return DWT_CYCCNT;
}
#endif /* RENODE_HAL_H */
