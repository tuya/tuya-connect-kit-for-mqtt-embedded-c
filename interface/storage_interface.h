#ifndef __STORAGE_INTERFACE_H_
#define __STORAGE_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The platform specific timer header that defines the Timer struct
 */
#include <stdint.h>
#include <stddef.h>

int local_storage_set(const char* key, const uint8_t* buffer, size_t length);

int local_storage_get(const char* key, uint8_t* buffer, size_t* length);

int local_storage_del(const char* key);

#ifdef __cplusplus
}
#endif

#endif //__TIMER_INTERFACE_H_
