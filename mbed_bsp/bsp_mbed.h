#ifndef _NM_BSP_MBED_H_
#define _NM_BSP_MBED_H_

#include <stdlib.h>
#include "mbed_debug.h"

#ifndef __cplusplus

// winc headers use this
typedef unsigned char bool;
enum { true = 1, false =0 };

#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#if !defined(WINC1500_NO_DEBUG) && MBED_WINC1500_ENABLE_DEBUG
#define CONF_WINC_PRINTF(...) printf( __VA_ARGS__ )
#elif !defined(WINC1500_NO_DEBUG) && !defined(MBED_WINC1500_ENABLE_DEBUG)
#define CONF_WINC_PRINTF(...) debug( __VA_ARGS__ )
#else
#define CONF_WINC_PRINTF(...) {}
#endif

#endif //_NM_BSP_MBED_H_

