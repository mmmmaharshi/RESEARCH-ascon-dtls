#ifndef EVAL_COMMON_HAL_H
#define EVAL_COMMON_HAL_H
#include <stdint.h>
/* unified HAL — Renode/QEMU/host. DWT (-DPQM4_DWT -O2) vs SysTick (-Os) vs rdtsc. HDR at 0x2000D000/0x2000E000. fallback retained */
#define HAL_HDR_ADDR 0x2000D000u
#define HAL_OUT_ADDR 0x2000E000u
#define HAL_OUT_SIZE 8192u
#define HAL_HDR_MAGIC 0x4D303032u
#define HAL_HEAP_LIMIT 0x20008000u
#define HAL_STACK_TOP 0x2000C000u
#define HAL_CPU_HZ 32000000u
#define HAL_DEMCR_ADDR 0xE000EDFCu
#define HAL_DWT_CTRL_ADDR 0xE0001000u
#define HAL_DWT_CYCCNT_ADDR 0xE0001004u
#define HAL_DEMCR (*(volatile uint32_t*)HAL_DEMCR_ADDR)
#define HAL_DWT_CTRL (*(volatile uint32_t*)HAL_DWT_CTRL_ADDR)
#define HAL_DWT_CYCCNT (*(volatile uint32_t*)HAL_DWT_CYCCNT_ADDR)
#define HAL_DEMCR_TRCENA (1u<<24)
#define HAL_DWT_CTRL_CYCCNTENA (1u<<0)
static inline void hal_dwt_enable(void){HAL_DEMCR|=HAL_DEMCR_TRCENA;HAL_DWT_CYCCNT=0;HAL_DWT_CTRL|=HAL_DWT_CTRL_CYCCNTENA;}
static inline uint32_t hal_dwt_now(void){return HAL_DWT_CYCCNT;}
#define HAL_SYST_CSR_ADDR 0xE000E010u
#define HAL_SYST_RVR_ADDR 0xE000E014u
#define HAL_SYST_CVR_ADDR 0xE000E018u
#define HAL_SYST_CSR (*(volatile uint32_t*)HAL_SYST_CSR_ADDR)
#define HAL_SYST_RVR (*(volatile uint32_t*)HAL_SYST_RVR_ADDR)
#define HAL_SYST_CVR (*(volatile uint32_t*)HAL_SYST_CVR_ADDR)
#define HAL_SYST_CTRL_COUNTFLAG (1u<<16)
#define HAL_SYST_CTRL_ENABLE_CLK 0x5u
static inline void hal_systick_enable(void){HAL_SYST_RVR=0x00FFFFFFu;HAL_SYST_CVR=0;HAL_SYST_CSR=HAL_SYST_CTRL_ENABLE_CLK;}
static inline uint32_t hal_systick_now(void){return HAL_SYST_CVR;}
static inline void hal_enable(void){
#ifdef PQM4_DWT
 hal_dwt_enable();
#else
 hal_systick_enable();
#endif
}
static inline uint32_t hal_now(void){
#ifdef PQM4_DWT
 return hal_dwt_now();
#else
 return hal_systick_now();
#endif
}
static inline uint32_t hal_elapsed(uint32_t s,uint32_t e){
#ifdef PQM4_DWT
 return e-s;
#else
 return (s-e)&0x00FFFFFFu;
#endif
}
static inline uint32_t hal_cc(void){return hal_now();}
#if defined(__x86_64__)||defined(__i386__)||defined(_M_IX86)||defined(_M_X64)
#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(__rdtsc)
static inline uint64_t hal_host_now(void){return __rdtsc();}
static inline void hal_host_lfence(void){}
#else
static inline uint64_t hal_host_now(void){unsigned lo,hi;__asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));return ((uint64_t)hi<<32)|lo;}
static inline void hal_host_lfence(void){__asm__ volatile("lfence":::"memory");}
#endif
#else
static inline uint64_t hal_host_now(void){return (uint64_t)hal_now();}
static inline void hal_host_lfence(void){}
#endif
#define DEMCR_ADDR HAL_DEMCR_ADDR
#define DWT_CTRL_ADDR HAL_DWT_CTRL_ADDR
#define DWT_CYCCNT_ADDR HAL_DWT_CYCCNT_ADDR
#ifndef DEMCR
#define DEMCR HAL_DEMCR
#define DWT_CTRL HAL_DWT_CTRL
#define DWT_CYCCNT HAL_DWT_CYCCNT
#endif
#define DEMCR_TRCENA HAL_DEMCR_TRCENA
#define DWT_CTRL_CYCCNTENA HAL_DWT_CTRL_CYCCNTENA
#endif
