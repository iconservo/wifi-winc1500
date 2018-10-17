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
#include "mbed-os/targets/TARGET_NORDIC/TARGET_NRF5x/TARGET_SDK_14_2/drivers_nrf/hal/nrf_gpio.h"


#ifdef CONF_WINC_USE_SPI
//#include <assert.h>

#include "mbed.h"
//#include <stdarg.h>
#include "mbed_debug.h"
#include "mbed_error.h"

//mbed specific GPIO handling
static DigitalOut SS_PIN(CONF_WINC_SPI_SS);
static SPI spi(CONF_WINC_SPI_MOSI, CONF_WINC_SPI_MISO, CONF_WINC_SPI_SCK); // mosi, miso, sclk

extern "C"
{

#include "winc1500/host_drv/bus_wrapper/include/nm_bus_wrapper.h"
    
    
#define NM_BUS_MAX_TRX_SZ       256


tstrNmBusCapabilities egstrNmBusCapabilities = {
        NM_BUS_MAX_TRX_SZ
};

int winc1500_spi_inited;



sint8
nm_bus_init(void *pvinit)
{

    spi.format(8,0);

    nrf_gpio_cfg(CONF_WINC_SPI_MOSI,
                 NRF_GPIO_PIN_DIR_INPUT,
                 NRF_GPIO_PIN_INPUT_CONNECT,
                 NRF_GPIO_PIN_NOPULL,
				 NRF_GPIO_PIN_H0H1,
                 NRF_GPIO_PIN_NOSENSE);

    nrf_gpio_cfg(CONF_WINC_SPI_SCK,
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
    int rc = 0;
    uint8_t tx = 0;
    uint8_t rx;

    /* chip select */
    SS_PIN.write(0);
    
    //sending one symbol at time
    while (u16Sz) {
        if (pu8Mosi) {
            tx = *pu8Mosi;
            pu8Mosi++;
        }

        rx = (uint8_t) spi.write((int)tx);

        if (pu8Miso) {
            *pu8Miso = rx;
            pu8Miso++;
        }
        u16Sz--;
    }

    //multiple SPI write
//    rc = spi.write((const char*)pu8Mosi, (int)u16Sz, (char*)pu8Miso, (int)u16Sz);

    /* chip deselect */
    SS_PIN.write(1);


    return rc;
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

