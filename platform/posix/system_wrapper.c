#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "system_interface.h"

/*
 * Time conversion constants.
 */
#define NANOSECONDS_PER_MILLISECOND    ( 1000000L )    /**< @brief Nanoseconds per millisecond. */
#define MILLISECONDS_PER_SECOND        ( 1000L )       /**< @brief Milliseconds per second. */


void* system_malloc(size_t n)
{
    return malloc(n);
}

void* system_calloc(size_t n, size_t size)
{
    return calloc(n, size);
}

void  system_free(void *ptr)
{
    free(ptr);
}

uint32_t system_ticks(void)
{
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    return (uint32_t)((current_time.tv_sec * 1000) + (current_time.tv_nsec / 1000000));
}

uint32_t system_timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)tv.tv_sec;
}

void system_sleep( uint32_t time_ms )
{
    /* Convert parameter to timespec. */
    struct timespec sleepTime = { 0 };

    sleepTime.tv_sec = ( ( time_t ) time_ms / ( time_t ) MILLISECONDS_PER_SECOND );
    sleepTime.tv_nsec = ( ( int64_t ) time_ms % MILLISECONDS_PER_SECOND ) * NANOSECONDS_PER_MILLISECOND;

    /* High resolution sleep. */
    ( void ) nanosleep( &sleepTime, NULL );
}

uint32_t system_random(void)
{
    return (uint32_t)rand();
}

#ifdef __cplusplus
}
#endif
