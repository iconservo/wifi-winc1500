#include "mbed.h"

extern "C"
{

	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_wifi.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/source/m2m_hif.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_types.h"

}

#define MAX_NUM_APs		10


class WINC1500Interface : public NetworkStack, public WiFiInterface {
public:
    virtual int connect();
    static WINC1500Interface& getInstance();
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


private:
    static void wifi_cb(uint8_t u8MsgType, void *pvMsg);
    static void wifi_thread_cb();

    static WINC1500Interface* instance;


	Thread wifi_thread;
	Semaphore got_scan_result, connected, disconnected;


	/** Index of scan list to request scan result. */
	static uint8_t scan_request_index;
	/** Number of APs found. */
	static uint8_t num_founded_ap;

	static nsapi_wifi_ap_t found_ap_list[MAX_NUM_APs];

	char ap_ssid[33]; /* 32 is what 802.11 defines as longest possible name; +1 for the \0 */
	tenuM2mSecType ap_sec;
	uint8_t ap_ch;
	char ap_pass[64]; /* The longest allowed passphrase */

//    WINC1500Interface();
    WINC1500Interface();
    WINC1500Interface(WINC1500Interface const&);              // Don't Implement.
    void operator=(WINC1500Interface const&); 					// Don't implement

//    static int connect_static();

};
