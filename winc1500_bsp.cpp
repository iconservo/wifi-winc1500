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

// #include "winc1500_priv.h"
#include "winc1500/host_drv/module_config/samd21/conf_winc.h"

#include "mbed.h"
//#include <stdarg.h>
#include "mbed_debug.h"
#include "mbed_error.h"

extern "C"{
    #include "winc1500/host_drv/bsp/include/nm_bsp.h"
    // #include "winc1500/host_drv/common/include/nm_common.h"

}
// #include "winc1500/host_drv/bus_wrapper/include/nm_bus_wrapper.h"

static InterruptIn winc_irq_pin((PinName)CONF_WINC_SPI_INT_PIN);
static DigitalOut reset_pin((PinName)CONF_WINC_SPI_INT_MUX);
static DigitalOut en_pin((PinName)CONF_WINC_SPI_INT_EIC);

void
nm_bsp_sleep(uint32 msec)
{
    // if (os_started()) {
    //     os_time_delay((msec * OS_TICKS_PER_SEC) / 1000);
    // } else {
    //     os_cputime_delay_usecs(msec * 1000);
    // }
    wait_ms(msec);
}

/*
 * Register interrupt handler
 */
void
nm_bsp_register_isr(tpfNmBspIsr isr)
{
    // int rc;
    // static uint8_t reg_done;

    // if (!reg_done) {
    //     rc = hal_gpio_irq_init(WINC1500_PIN_IRQ, (hal_gpio_irq_handler_t)isr,
    //                            NULL, HAL_GPIO_TRIG_FALLING, HAL_GPIO_PULL_UP);
    //     assert(rc == 0);
    //     reg_done = 1;
    // }
    // hal_gpio_irq_enable(WINC1500_PIN_IRQ);

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
        // hal_gpio_irq_enable(WINC1500_PIN_IRQ);
    } else {
        winc_irq_pin.disable_irq();
        // hal_gpio_irq_disable(WINC1500_PIN_IRQ);
    }
}

/*
 * Reset NMC1500 SoC by setting CHIP_EN and RESET_N signals low,
 * CHIP_EN high then RESET_N high
 */
void
nm_bsp_reset(void)
{
    // hal_gpio_write(WINC1500_PIN_ENABLE  , 0);
    en_pin.write(0);
    reset_pin.write(0);
    // hal_gpio_write(MBED_CONF_WINC1500_WIFI_RESET, 0);
    nm_bsp_sleep(100); /* 100ms */

    en_pin.write(0);
    // hal_gpio_write(WINC1500_PIN_ENABLE, 1);
    nm_bsp_sleep(10); /* 10ms */
    reset_pin.write(0);
    // hal_gpio_write(MBED_CONF_WINC1500_WIFI_RESET, 1);
    nm_bsp_sleep(10); /* 10ms */
}
