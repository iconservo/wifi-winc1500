
/** \addtogroup netsocket */
/** @{*/
/* TCPSocket
 * Copyright (c) 2015 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WINC1500TLSSOCKET_H
#define WINC1500TLSSOCKET_H

#include "netsocket/TCPSocket.h"
#include "wifi-winc1500/WINC1500Interface.h"
#include "netsocket/Socket.h"
#include "TCPSocket.h"
#include "netsocket/NetworkStack.h"
#include "netsocket/NetworkInterface.h"
#include "rtos/EventFlags.h"


/** TCP socket connection
 */
class WINC1500TLSSocket : public TCPSocket {
public:



    /** Opens a socket
         *
         *  Creates a network socket on the network stack of the given
         *  network interface. Not needed if stack is passed to the
         *  socket's constructor.
         *
         *  @param stack    Network stack as target for socket
         *  @return         0 on success, negative error code on failure
         */
    nsapi_error_t open(WINC1500Interface *stack);

protected:
    friend class TCPServer;
    friend class NetworkStack;
    friend class Socket;

    virtual nsapi_protocol_t get_proto();
    virtual void event();

};


#endif

/** @}*/
