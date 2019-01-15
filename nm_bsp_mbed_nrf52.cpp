/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "mbed.h"
#include "mbed_debug.h"
#include "mbed_error.h"
#define _Static_assert(...);

extern "C"{
    #include "nm_bsp.h"
	#include "bsp_mbed.h"
}


static InterruptIn winc_irq_pin(MBED_CONF_WINC1500_WIFI_IRQ);
static DigitalOut reset_pin(MBED_CONF_WINC1500_WIFI_RESET);
static DigitalOut en_pin(MBED_CONF_WINC1500_WIFI_CHIP_ENABLE);
static DigitalOut wake_pin(MBED_CONF_WINC1500_WIFI_WAKEUP);


static tpfNmBspIsr gpfIsr;

static void chip_isr(void)
{
	if (gpfIsr) {
		gpfIsr();
	}
}


/*
 *	@fn		init_chip_pins
 *	@brief	Initialize reset, chip enable and wake pin
 */
static void init_chip_pins(void)
{
	reset_pin.write(0);
	en_pin.write(0);
	wake_pin.write(0);
}


/*
 *	@fn		nm_bsp_init
 *	@brief	Initialize BSP
 *	@return	0 in case of success and -1 in case of failure
 */
sint8 nm_bsp_init(void)
{
	gpfIsr = NULL;

	/* Initialize chip IOs. */
	init_chip_pins();

	nm_bsp_reset();


	return 0;
}

/**
 *	@fn		nm_bsp_deinit
 *	@brief	De-iInitialize BSP
 *	@return	0 in case of success and -1 in case of failure
 */
sint8 nm_bsp_deinit(void)
{

	reset_pin.write(0);
	en_pin.write(0);
	wake_pin.write(0);

	winc_irq_pin.mode(PullNone);

	return 0;
}


/*
 *	@fn		nm_bsp_sleep
 *	@brief	Sleep in units of mSec
 *	@param[IN]	u32TimeMsec
 *				Time in milliseconds
 */
void nm_bsp_sleep(uint32 u32TimeMsec)
{
	wait_ms(u32TimeMsec);
}


/*
 * Register interrupt handler
 */
void
nm_bsp_register_isr(tpfNmBspIsr isr)
{
    winc_irq_pin.fall(isr);
}

/*
 * Enable/disable interrupt
 */
void
nm_bsp_interrupt_ctrl(uint8 enable)
{
    if (enable) {
        winc_irq_pin.enable_irq();
    } else {
        winc_irq_pin.disable_irq();
    }
}

/**
 *	@fn		nm_bsp_reset
 *	@brief	Reset NMC1500 SoC by setting CHIP_EN and RESET_N signals low,
 *           CHIP_EN high then RESET_N high
 */
void nm_bsp_reset(void)
{

	reset_pin.write(0);
	en_pin.write(0);

	nm_bsp_sleep(100);
	en_pin.write(1);

	nm_bsp_sleep(10);
	reset_pin.write(1);
	wake_pin.write(1);

	nm_bsp_sleep(10);

}

