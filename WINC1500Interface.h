#include "mbed.h"


#include "wifi-winc1500/mbed_bsp/bsp_mbed.h"

extern "C"
{
	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_wifi.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/source/m2m_hif.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_types.h"
	#include "wifi-winc1500/mbed_winc1500_socket/include/winc1500_socket.h"
}

#define MAX_NUM_APs		10

#define WINC1500_SOCK_RX_SIZE       1500

//#define winc_debug(...)

#define winc_debug(cond, ...) 	\
	if (cond) \
	{			\
		printf("DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __func__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	}			\

#define IPV4_BYTE(val, index)       ((val >> (index * 8)) & 0xFF)


struct WINC1500_socket {
    int id;
    nsapi_protocol_t proto;
    volatile bool connected;
    SocketAddress addr;
    char read_data[WINC1500_SOCK_RX_SIZE];
    volatile uint32_t read_data_size;
};


typedef union ip_addr_t{
	uint8_t ip_addr_8[4];
	uint32_t ip_addr_32;
};


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

    static WINC1500Interface* instance;


	Thread wifi_thread;
	Semaphore got_scan_result, connected, disconnected;


	//socket related private variables
	Thread socket_thread;
    Mutex _mutex;
    Semaphore socket_connected, socket_dns_resolved, socket_data_sent, socket_data_recv;

    bool _ids[MAX_SOCKET];
    uint32_t _socket_obj[MAX_SOCKET]; // store addresses of socket handles
    struct WINC1500_socket _socker_arr[MAX_SOCKET];

//    Semaphore socket_open;
    bool _winc_debug;

    ip_addr_t IP_addr;

	/** Index of scan list to request scan result. */
	static uint8_t scan_request_index;
	/** Number of APs found. */
	static uint8_t num_founded_ap;

	static nsapi_wifi_ap_t found_ap_list[MAX_NUM_APs];

	char ap_ssid[33]; /* 32 is what 802.11 defines as longest possible name; +1 for the \0 */
	tenuM2mSecType ap_sec;
	uint8_t ap_ch;
	char ap_pass[64]; /* The longest allowed passphrase */

	struct sockaddr_in current_sock_addr;

	static int current_socket_send_ID;
	static int read_data_size;
	char received_data[64];
	uint16_t received_data_size;

//    WINC1500Interface();
    WINC1500Interface();
    WINC1500Interface(WINC1500Interface const&);              // Don't Implement.
    void operator=(WINC1500Interface const&); 					// Don't implement

    static void wifi_cb(uint8_t u8MsgType, void *pvMsg);
    static void wifi_thread_cb();
//    static int winc1500_mn_addrto_addr(struct mn_sockaddr_in *msin, struct sockaddr_in *sin);
    static int winc1500_err_to_mn_err(int err);
    static void socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg);
    static void dnsResolveCallback(uint8* pu8HostName ,uint32 u32ServerIP);

};
