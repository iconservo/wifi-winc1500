#ifndef WINC1500TLSSOCKET_H
#define WINC1500TLSSOCKET_H

#include "TCPSocket.h"
#include "WINC1500Interface.h"
#include "netsocket/Socket.h"
#include "TCPSocket.h"
#include "NetworkStack.h"
#include "NetworkInterface.h"
#include "EventFlags.h"

/** WINC1500 TLS socket connection
 */
class WINC1500TLSSocket : public TCPSocket {
   public:
    /** Opens a winc1500 TLS socket
     *
     *  Creates a network socket on the network stack of the given
     *  network interface. Not needed if stack is passed to the
     *  socket's constructor.
     *
     *  @param stack    WINC1500Interface Network stack as target for socket
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t open(WINC1500Interface* stack);

   protected:
    friend class TCPServer;
    friend class NetworkStack;
    friend class Socket;

    virtual nsapi_protocol_t get_proto();
    virtual void event();
};

#endif

/** @}*/
