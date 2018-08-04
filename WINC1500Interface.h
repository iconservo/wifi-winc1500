#include "mbed.h"

class WINC1500Interface : public NetworkStack, public WiFiInterface {
public:
    WINC1500Interface();
    virtual int connect();

    virtual int connect(const char *ssid, const char *pass, nsapi_security_t security = NSAPI_SECURITY_NONE,
                        uint8_t channel = 0);
    virtual nsapi_error_t gethostbyname(const char *name, SocketAddress *address, nsapi_version_t version = NSAPI_UNSPEC);
    virtual int set_credentials(const char *ssid, const char *pass, nsapi_security_t security = NSAPI_SECURITY_NONE);
    virtual int set_channel(uint8_t channel);
    virtual int disconnect();
    virtual const char *get_ip_address();
    virtual const char *get_mac_address();
    virtual const char *get_gateway();
    virtual const char *get_netmask();
    virtual int8_t get_rssi();
    virtual int scan(WiFiAccessPoint *res, unsigned count);

protected:
    virtual int socket_open(void **handle, nsapi_protocol_t proto);
    virtual int socket_close(void *handle);
    virtual int socket_bind(void *handle, const SocketAddress &address);
    virtual int socket_listen(void *handle, int backlog);
    virtual int socket_connect(void *handle, const SocketAddress &address);
    virtual int socket_accept(void *handle, void **socket, SocketAddress *address);
    virtual int socket_send(void *handle, const void *data, unsigned size);
    virtual int socket_recv(void *handle, void *data, unsigned size);
    virtual int socket_sendto(void *handle, const SocketAddress &address, const void *data, unsigned size);
    virtual int socket_recvfrom(void *handle, SocketAddress *address, void *buffer, unsigned size);
    virtual void socket_attach(void *handle, void (*callback)(void *), void *data);
    virtual NetworkStack *get_stack()
    {
        return this;
    }

};
