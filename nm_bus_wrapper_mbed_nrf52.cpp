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
#include "mbed_bsp/bsp_mbed.h"
#include "nrf_gpio.h"


#ifdef CONF_WINC_USE_SPI
//#include <assert.h>

#include "mbed.h"
//#include <stdarg.h>
#include "mbed_debug.h"
#include "mbed_error.h"

// mosi, miso, sclk, ssel
SPI spi(MBED_CONF_WINC1500_WIFI_MOSI, MBED_CONF_WINC1500_WIFI_MISO, MBED_CONF_WINC1500_WIFI_SCLK, MBED_CONF_WINC1500_WIFI_NSS);

extern "C"
{

#include "nm_bus_wrapper.h"
    
    
#define NM_BUS_MAX_TRX_SZ       256


tstrNmBusCapabilities egstrNmBusCapabilities = {
        NM_BUS_MAX_TRX_SZ
};

int winc1500_spi_inited;



sint8
nm_bus_init(void *pvinit)
{

    spi.format(8,0);
    spi.set_default_write_value(0x00);
    spi.frequency(8000000);

    nrf_gpio_cfg(MBED_CONF_WINC1500_WIFI_MOSI,
                 NRF_GPIO_PIN_DIR_INPUT,
                 NRF_GPIO_PIN_INPUT_CONNECT,
                 NRF_GPIO_PIN_NOPULL,
				 NRF_GPIO_PIN_H0H1,
                 NRF_GPIO_PIN_NOSENSE);

    nrf_gpio_cfg(MBED_CONF_WINC1500_WIFI_MISO,
                 NRF_GPIO_PIN_DIR_INPUT,
                 NRF_GPIO_PIN_INPUT_CONNECT,
                 NRF_GPIO_PIN_NOPULL,
				 NRF_GPIO_PIN_H0H1,
                 NRF_GPIO_PIN_NOSENSE);

    nrf_gpio_cfg(MBED_CONF_WINC1500_WIFI_SCLK,
                     NRF_GPIO_PIN_DIR_INPUT,
                     NRF_GPIO_PIN_INPUT_CONNECT,
                     NRF_GPIO_PIN_NOPULL,
					 NRF_GPIO_PIN_H0H1,
                     NRF_GPIO_PIN_NOSENSE);

    nm_bsp_reset();
    nm_bsp_sleep(1);


    return 0;
}

sint8
nm_bus_deinit(void)
{
    /*
     * Disable SPI.
     */
    return 0;
}

static sint8
nm_spi_rw(uint8 *pu8Mosi, uint8 *pu8Miso, uint16 u16Sz)
{

	spi.write((char *)pu8Mosi, pu8Mosi ? u16Sz : 0, (char *)pu8Miso, pu8Miso ? u16Sz : 0);

    return 0;
}

sint8
nm_bus_ioctl(uint8 cmd, void *arg)
{
    tstrNmSpiRw *param;

    if (cmd != NM_BUS_IOCTL_RW) {
        return -1;
    }
    param = (tstrNmSpiRw *)arg;

    return nm_spi_rw(param->pu8InBuf, param->pu8OutBuf, param->u16Sz);
}
}
#endif

