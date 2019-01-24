#ifndef _NM_BSP_MBED_H_
#define _NM_BSP_MBED_H_

#include <stdlib.h>
#include "mbed_debug.h"

#ifdef __cplusplus
extern "C"
{
#endif

void printf_all(const char* format, ...);

#ifndef __cplusplus
// winc headers use this in C compile mode
typedef unsigned char bool;
enum { true = 1, false =0 };

#endif

#define _Static_assert(...);

#undef CONF_WINC_USE_SPI
#define CONF_WINC_USE_SPI				(1)


#define CONF_WINC_PIN_RESET				p14 /* PIN_PA27 */
#define CONF_WINC_PIN_CHIP_ENABLE		p11 /* PIN_PA28 */
#define CONF_WINC_PIN_WAKE				p16 /* PIN_PB08 */


#define LOW_POWER_ENABLE				p9
/*
---------------------------------
   ---------- SPI settings ---------
   ---------------------------------
*/

/* Flash Chip Select pin */
#define FLASH_SS						p24

/** SPI pin and instance settings. */
#define CONF_WINC_SPI_MODULE			0 /* SERCOM2 */
#define CONF_WINC_SPI_SERCOM_MUX		0 /* SPI_SIGNAL_MUX_SETTING_D */
#define CONF_WINC_SPI_PINMUX_PAD0		0 /* PINMUX_PA12C_SERCOM2_PAD0 */ /* out */
#define CONF_WINC_SPI_PINMUX_PAD1		0 /* PINMUX_PA13C_SERCOM2_PAD1 */ /* sck  */
#define CONF_WINC_SPI_PINMUX_PAD2		0 /* PINMUX_UNUSED */ /* cs driven from software */
#define CONF_WINC_SPI_PINMUX_PAD3		0 /* PINMUX_PA15C_SERCOM2_PAD3 */ /* in  */
#define CONF_WINC_SPI_CS_PIN			0 /* PIN_PA14 */

#define CONF_WINC_SPI_MOSI				p25 /* PIN_PA12 */
#define CONF_WINC_SPI_SCK				p29 /* PIN_PA13 */
#define CONF_WINC_SPI_SS				p12 /* PIN_PA14 */
#define CONF_WINC_SPI_MISO				p28 /* PIN_PA15 */

/** SPI interrupt pin. */
#define CONF_WINC_SPI_INT_PIN			p15 /* PIN_PB09A_EIC_EXTINT9 */
#define CONF_WINC_SPI_INT_MUX			0 /* MUX_PB09A_EIC_EXTINT9 */
#define CONF_WINC_SPI_INT_EIC			0 /* (9) */

/** SPI clock. */
#define CONF_WINC_SPI_CLOCK				(12000000)

/*
   ---------------------------------
   --------- Debug Options ---------
   ---------------------------------
*/

#undef CONF_WINC_DEBUG
#define CONF_WINC_DEBUG					        (1)

#define M2M_LOG_NONE									0
#define M2M_LOG_ERROR								1
#define M2M_LOG_INFO									2
#define M2M_LOG_REQ									3
#define M2M_LOG_DBG									4


#define CONF_WINC_PRINTF(...)                printf( __VA_ARGS__ )


#undef M2M_LOG_LEVEL
#define M2M_LOG_LEVEL								M2M_LOG_DBG


#define M2M_ERR(...)
#define M2M_INFO(...)
#define M2M_REQ(...)
#define M2M_DBG(...)
#define M2M_PRINT(...)

#if (CONF_WINC_DEBUG == 1)
#undef M2M_PRINT
#define M2M_PRINT(...)							do{CONF_WINC_PRINTF(__VA_ARGS__);}while(0)
#if (M2M_LOG_LEVEL >= M2M_LOG_ERROR)
#undef M2M_ERR
#define M2M_ERR(...)							do{CONF_WINC_PRINTF("(APP)(ERR)[%s][%d]",__FUNCTION__,__LINE__); CONF_WINC_PRINTF(__VA_ARGS__);CONF_WINC_PRINTF("\r");}while(0)
#if (M2M_LOG_LEVEL >= M2M_LOG_INFO)
#undef M2M_INFO
#define M2M_INFO(...)							do{CONF_WINC_PRINTF("(APP)(INFO)"); CONF_WINC_PRINTF(__VA_ARGS__);CONF_WINC_PRINTF("\r");}while(0)
#if (M2M_LOG_LEVEL >= M2M_LOG_REQ)
#undef M2M_REQ
#define M2M_REQ(...)							do{CONF_WINC_PRINTF("(APP)(R)"); CONF_WINC_PRINTF(__VA_ARGS__);CONF_WINC_PRINTF("\r");}while(0)
#if (M2M_LOG_LEVEL >= M2M_LOG_DBG)
#undef M2M_DBG
#define M2M_DBG(...)							do{CONF_WINC_PRINTF("(APP)(DBG)[%s][%d]",__FUNCTION__,__LINE__); CONF_WINC_PRINTF(__VA_ARGS__);CONF_WINC_PRINTF("\r");}while(0)
#endif /*M2M_LOG_DBG*/
#endif /*M2M_LOG_REQ*/
#endif /*M2M_LOG_INFO*/
#endif /*M2M_LOG_ERROR*/
#endif /*CONF_WINC_DEBUG */

#ifdef __cplusplus
}
#endif


#endif //_NM_BSP_MBED_H_