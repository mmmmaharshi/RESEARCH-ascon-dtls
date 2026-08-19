/* Forward declarations injected into benchmark.c (-include) so its
 * remapped printf/current_time calls have prototypes. */
double bench_current_time(int reset);
void bench_xprintf(const char* fmt, ...);