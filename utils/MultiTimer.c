#include "MultiTimer.h"
#include <stdio.h>

#define MULTIMER_MAX_TIMEOUT  0x7fffffff

/* Check if timer's expiry time is greater than time and care about uint32_t wraparounds */
#define CHECK_TIME_LESS_THAN(t, compare_to) ( (((uint32_t)((t)-(compare_to))) > MULTIMER_MAX_TIMEOUT) ? 1 : 0 )

/* Timer handle list head. */
static MultiTimer* timerList = NULL;

/* Timer tick */
static PlatformTicksFunction_t platformTicksFunction = NULL;

/**
 * @brief 
 * 
 * @param ticksFunc 
 * @return int 
 */
int MultiTimerInstall(PlatformTicksFunction_t ticksFunc)
{
    platformTicksFunction = ticksFunc;
    return 0;
}

/**
  * @brief  Initializes the timer struct handle.
  * @param  handle: the timer handle strcut.
  * @param  timeout_cb: deadline callback.
  * @param  repeat: repeat interval time.
  * @retval None
  */
int MultiTimerInit(MultiTimer* timer, uint32_t period, MultiTimerCallback_t cb, void* userData)
{
    if (!timer || !cb) {
        return -1;
    }
    timer->callback = cb;
    timer->userData = userData;
    timer->period = period;
    return 0;
}

/**
  * @brief  Start the timer work, add the handle into work list.
  * @param  handle: target handle strcut.
  * @param  deadline: Set the start time.
  * @retval 0: succeed. -1: already exist.
  */
int MultiTimerStart(MultiTimer* timer, uint32_t startTime)
{
    MultiTimer** nextTimer = &timerList;

    /* Remove the existing target timer. */
    for (; *nextTimer; nextTimer = &(*nextTimer)->next) {
        if (timer == *nextTimer) {
            *nextTimer = timer->next; /* remove from list */
            break;
        }
    }

    /* New deadline time. */
    timer->deadline = platformTicksFunction() + startTime;

    /* Insert timer. */
    for (nextTimer = &timerList;; nextTimer = &(*nextTimer)->next) {
        if (!*nextTimer) {
            timer->next = NULL;
            *nextTimer = timer;
            break;
        }
        if (timer->deadline < (*nextTimer)->deadline) {
            timer->next = *nextTimer;
            *nextTimer = timer;
            break;
        }
    }
    return 0;
}

/**
  * @brief  Stop the timer work, remove the handle off work list.
  * @param  handle: target handle strcut.
  * @retval None
  */
int MultiTimerStop(MultiTimer* timer)
{
    MultiTimer** nextTimer = &timerList;

    /* Find and remove timer. */
    for (; *nextTimer; nextTimer = &(*nextTimer)->next) {
        MultiTimer* entry = *nextTimer;
        if (entry == timer) {
            *nextTimer = timer->next;
            break;
        }
    }
    return 0;
}

/**
 * @brief MultiTimer is activated?
 * 
 * @param timer 
 * @return true 
 * @return false 
 */
bool MultiTimerActivated(MultiTimer* timer)
{
    MultiTimer* entry = timerList;
    while (entry) {
        if (entry == timer) {
            return true;
        }
        entry = entry->next;
    }
    return false;
}

/**
  * @brief  main loop.
  * @param  None.
  * @retval None
  */
void MultiTimerYield(void)
{
    MultiTimer** nextTimer = &timerList;

    for (; *nextTimer; nextTimer = &(*nextTimer)->next) {
        MultiTimer* entry = *nextTimer;
        /* Sorted list, just process with the front part. */
        if (CHECK_TIME_LESS_THAN(platformTicksFunction(), entry->deadline)) {
            return;
        }
        /* remove expired timer from list */
        *nextTimer = entry->next;

        if (entry->period) {
            MultiTimerStart(entry, entry->period);
        }
        if (entry->callback) {
            entry->callback(entry, entry->userData);
        }
        if (entry->next == NULL) {
            return;
        }
    }
}
