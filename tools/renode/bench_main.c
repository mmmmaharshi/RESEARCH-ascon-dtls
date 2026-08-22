/* Bare-metal wolfCrypt benchmark driver for Renode (Cortex-M0+/M3).
 * - current_time: SysTick (32 MHz, 24-bit, COUNTFLAG wrap tracking)
 * - printf (XPRINTF): appends to an SRAM buffer read back by the host
 *   after the emulation is paused.
 * Results: header at 0x2003D000 (magic/out_addr/out_len/done),
 *          text at 0x2003E000. Region sits above __stack_top (0x2003C000),
 *          so neither the heap (capped at 0x20038000) nor the stack can
 *          clobber it. SRAM is 256 KB in the .repl to map these addresses. */
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include "benchmark.h"
void record_bench(void);

#ifdef PQM4_DWT
#include "hal.h"
#else
#define SYST_CSR (*(volatile uint32_t*)0xE000E010u)
#define SYST_RVR (*(volatile uint32_t*)0xE000E014u)
#define SYST_CVR (*(volatile uint32_t*)0xE000E018u)
#define CTRL_COUNTFLAG (1u << 16)
#define CTRL_ENABLE_CLK (0x5u) /* ENABLE | CLKSOURCE */
#endif

#define HDR_ADDR  0x2003D000u
#define OUT_ADDR  0x2003E000u
#define OUT_SIZE  8192u
#define HDR_MAGIC 0x4D303032u /* "M002" */

static volatile uint32_t* hdr = (volatile uint32_t*)HDR_ADDR;
static volatile char*      out = (volatile char*)OUT_ADDR;

static uint32_t s_wraps;
static uint32_t s_start;

#ifdef PQM4_DWT
static uint32_t dwt_start;
#endif

/* Real heap (nosys _sbrk stub returns ENOMEM). `end` is the heap start
 * symbol from bench.ld (end = __heap_start). Capped below the reserved
 * output region / stack so it can't overwrite the result buffer. */
extern char end;
#define HEAP_LIMIT 0x20038000u
void* _sbrk(ptrdiff_t incr)
{
    static char* heap = NULL;
    if (heap == NULL) {
        heap = &end;
    }
    char* prev = heap;
    char* next = heap + incr;
    if (next > (char*)HEAP_LIMIT) {
        return (void*)-1; /* OOM */
    }
    heap = next;
    return prev;
}

/* benchmark.c calls this via WOLFSSL_CURRTIME_REMAP */
double bench_current_time(int reset)
{
#ifdef PQM4_DWT
    if (reset) {
        hal_dwt_enable();
        dwt_start = hal_cc();
        return 0.0;
    }
    return (double)(hal_cc() - dwt_start) / 32000000.0;
#else
    if (reset) {
        s_wraps = 0;
        s_start = SYST_CVR;
        return 0.0;
    }
    if (SYST_CSR & CTRL_COUNTFLAG) {
        s_wraps++;
    }
    uint32_t elapsed = (s_start - SYST_CVR) & 0x00FFFFFFu;
    /* one COUNTFLAG wrap may be missed per read (0.5 s transient),
     * averaged out over the >= 1 s benchmark runs */
    return ((double)s_wraps * 0x1000000u + (double)elapsed) / 32000000.0;
#endif
}

/* benchmark.c printf() is remapped to this via XPRINTF */
void bench_xprintf(const char* fmt, ...)
{
    uint32_t len = hdr[2];
    uint32_t avail = (len < OUT_SIZE) ? OUT_SIZE - len : 0;
    if (avail == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf((char*)(out + len), avail, fmt, ap);
    va_end(ap);
    if (n > 0) {
        len += (n < (int)avail) ? (uint32_t)n : (avail - 1);
        hdr[2] = len;
    }
}

int main(void)
{
    hdr[0] = HDR_MAGIC;
    hdr[1] = OUT_ADDR;
    hdr[2] = 0;
    hdr[3] = 0;
    out[0] = 0;

#ifdef PQM4_DWT
    hal_dwt_enable();
#else
    SYST_RVR = 0x00FFFFFFu;
    SYST_CVR = 0;
    SYST_CSR = CTRL_ENABLE_CLK;
#endif

    int rc = benchmark_test(NULL);
    record_bench();
    hdr[3] = 1; /* done */
    return rc;
}