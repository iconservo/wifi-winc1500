#include "WINC1500Interface.h"

WINC1500Interface::WINC1500Interface() {

}

int WINC1500Interface::connect(const char *ssid, const char *pass, nsapi_security_t security,
                               uint8_t channel)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::connect()
{
    return NSAPI_ERROR_UNSUPPORTED;
}

nsapi_error_t WINC1500Interface::gethostbyname(const char *name, SocketAddress *address, nsapi_version_t version)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::set_channel(uint8_t channel)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::disconnect()
{
    return NSAPI_ERROR_UNSUPPORTED;
}

const char *WINC1500Interface::get_ip_address()
{
    return "ERROR";
}

const char *WINC1500Interface::get_mac_address()
{
    return "ERROR";
}

const char *WINC1500Interface::get_gateway()
{
    return "ERROR";
}

const char *WINC1500Interface::get_netmask()
{
    return "ERROR";
}

int8_t WINC1500Interface::get_rssi()
{
    return -1;
}

int WINC1500Interface::scan(WiFiAccessPoint *res, unsigned count)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

struct WINC1500Socket {
    int id;
};

int WINC1500Interface::socket_open(void **handle, nsapi_protocol_t proto)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_close(void *handle)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_bind(void *handle, const SocketAddress &address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_listen(void *handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_connect(void *handle, const SocketAddress &addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_send(void *handle, const void *data, unsigned size)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_recv(void *handle, void *data, unsigned size)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

void WINC1500Interface::socket_attach(void *handle, void (*cb)(void *), void *data)
{
}

