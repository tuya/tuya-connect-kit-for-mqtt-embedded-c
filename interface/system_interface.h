#ifndef __SYSTEM_INTERFACE_H_
#define __SYSTEM_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void* system_malloc(size_t n);

void* system_calloc(size_t n, size_t size);

void  system_free(void *ptr);

uint32_t system_ticks(void);

uint32_t system_timestamp(void);

void system_sleep(uint32_t time_ms);

uint32_t system_random(void);

#ifdef __cplusplus
}
#endif

#endif //__TIMER_INTERFACE_H_
