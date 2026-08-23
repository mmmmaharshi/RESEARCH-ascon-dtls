/* Probe: bare-metal SysTick timing on Renode Cortex-M. Results in SRAM. */
#include <stdint.h>

#define SYST_CSR (*(volatile uint32_t*)0xE000E010u)
#define SYST_RVR (*(volatile uint32_t*)0xE000E014u)
#define SYST_CVR (*(volatile uint32_t*)0xE000E018u)

/* Result block read back from the Renode monitor after pause. */
#define RESULT_ADDR 0x20002000u
#define RESULT_MAGIC 0x4D303031u /* "M001" */
typedef struct {
    uint32_t magic;
    uint32_t elapsed_ticks;
    uint32_t done;
} result_t;
static volatile result_t* result = (volatile result_t*)RESULT_ADDR;

static void systick_init(void)
{
    SYST_RVR = 0x00FFFFFFu;
    SYST_CVR = 0;
    SYST_CSR = 0x5; /* ENABLE | CLKSOURCE, no interrupt */
}

static uint32_t systick_elapsed(uint32_t start)
{
    return (start - SYST_CVR) & 0x00FFFFFFu;
}

int main(void)
{
    result->magic = RESULT_MAGIC;
    result->elapsed_ticks = 0;
    result->done = 0;
    systick_init();
    {
        uint32_t start = SYST_CVR;
        volatile uint32_t i;
        for (i = 0; i < 1000000u; i++) { }
        result->elapsed_ticks = systick_elapsed(start);
    }
    result->done = 1;
    return 0;
}