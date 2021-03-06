

#ifndef WINC1500INTERFACE_H
#define WINC1500INTERFACE_H

#include "mbed.h"
#include "wifi-winc1500/mbed_bsp/bsp_mbed.h"
#include "platform/CircularBuffer.h"

extern "C" {
#include "m2m_wifi.h"
#include "m2m_hif.h"
#include "m2m_types.h"
#include "winc1500_socket.h"
#include "spi_flash.h"
#include "spi_flash_map.h"
#include "m2m_ota.h"
#include "driver/source/nmasic.h"
#include "driver/source/nmspi.h"
#include "driver/source/nmbus.h"
}

#ifndef MAX_NUM_APs
#define MAX_NUM_APs 10
#endif

#ifndef WINC1500_SOCK_RX_SIZE
#define WINC1500_SOCK_RX_SIZE SOCKET_BUFFER_MAX_LENGTH
#endif

#define SSID_LEN 6

#undef MAX_SOCKET
#define MAX_SOCKET 3

// Various timeouts for different WINC1500 operations
#define WINC1500_CONNECT_TIMEOUT 15000    /* milliseconds */
#define WINC1500_DNS_RESOLVE_TIMEOUT 1000 /* milliseconds */
#define WINC1500_DISCONNECT_TIMEOUT 1000  /* milliseconds */
#define WINC1500_SCAN_RESULT_TIMEOUT 5000 /* milliseconds */
#define WINC1500_SEND_TIMEOUT 5000        /* milliseconds */
#define WINC1500_RECV_TIMEOUT 10000        /* milliseconds */

#define WINC1500_MAX_MAJOR_VERSION 30

#define winc_debug(cond, ...)                                        \
    if (cond) {                                                      \
        printf("DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __func__); \
        printf(__VA_ARGS__);                                         \
        printf("\n");                                                \
    }

#define IPV4_BYTE(val, index) ((val >> (index * 8)) & 0xFF)

// macro for printing error messages
#define CASE_ENUM_ENTITY_STR_RETURN(mnemonic) \
    case mnemonic: {                          \
        return #mnemonic;                     \
    }

struct WINC1500_socket {
    int id;
    nsapi_protocol_t proto;
    bool connected;
    bool opened;
    SocketAddress addr;
    //cirlular buffer
    CircularBuffer<uint8_t, WINC1500_SOCK_RX_SIZE*2> circ_buff;
    uint8_t chunk_buff[1024];

    uint32_t received_data_size;
    /**
     * TCP port number of HTTP.
     */
    uint16_t port;
    /**
     * A flag for the whether using the TLS socket or not.
     */
    uint8_t tls;

    /* callback, callback data and two flags for polling recv and notifying mbed cloud client
    */
    void (*callback)(void *);
    void *callback_data;
    bool recv_req_pending, recv_in_progress;

    //consructor 
    WINC1500_socket() : 
        id(0), 
        proto(NSAPI_TCP), 
        connected(false), 
        addr(),
        received_data_size(0), 
        port(0), 
        tls(0),
        callback(NULL),
        callback_data(NULL),
        recv_req_pending(false), 
        recv_in_progress(false) {
    }
};

struct connection_info {
    uint32 u32IP;
    uint32 u32Gateway;
    uint32 u32SubnetMask;
    sint8 rssi;
};

struct ap_connection_info {
    char ap_SSID[M2M_MAX_SSID_LEN];
	/*!< AP connection SSID name  */
	uint8_t	sec_type;
	/*!< Security type */
	uint8_t	ip_addr[4];
	/*!< Connection IP address */
	uint8_t	mac_addr[6];
	/*!< MAC address of the peer Wi-Fi station */ 
	int	rssi;
	/*!< Connection RSSI signal */
	uint8_t	current_channel; 
	/*!< Wi-Fi RF channel number  1,2,... 14.  */
};

class WINC1500Interface : public NetworkStack, public WiFiInterface {
   public:
    virtual int connect();
    static WINC1500Interface& getInstance();
    virtual int connect(const char* ssid,
                        const char* pass,
                        nsapi_security_t security = NSAPI_SECURITY_NONE,
                        uint8_t channel = 0);
    virtual nsapi_error_t gethostbyname(const char* name,
                                        SocketAddress* address,
                                        nsapi_version_t version = NSAPI_UNSPEC);
    virtual int set_credentials(const char* ssid, const char* pass, nsapi_security_t security = NSAPI_SECURITY_NONE);
    virtual int set_channel(uint8_t channel);
    virtual int disconnect();
    virtual const char* get_ip_address();
    virtual const char* get_mac_address();
    virtual const char* get_gateway();
    virtual const char* get_netmask();
    virtual int8_t get_rssi();
    virtual int8_t get_channel();
    virtual int scan(WiFiAccessPoint* res, unsigned count);
    const char* get_otp_mac_address();
    int set_mac_address(const uint8* mac_address);
    int winc_flash_read(char *str, const char *addr, const char *num);
    int winc_write_chip(const unsigned char *data, unsigned int data_len);
    int winc_download_mode(void);
    int winc_get_version(char *str, int len);
    int winc_chip_erase(void);
    int winc_write_ota(const unsigned char *data, unsigned int data_len);
    int winc_switch_part(void);
    int chip_init(uint8_t* mac_buffer = NULL);
    void iface_disable(void);

   protected:
    virtual int socket_open(void** handle, nsapi_protocol_t proto);
    virtual int socket_close(void* handle);
    virtual int socket_bind(void* handle, const SocketAddress& address);
    virtual int socket_listen(void* handle, int backlog);
    virtual int socket_connect(void* handle, const SocketAddress& address);
    virtual int socket_accept(void* handle, void** socket, SocketAddress* address);
    virtual int socket_send(void* handle, const void* data, unsigned size);
    virtual int socket_recv(void* handle, void* data, unsigned size);
    virtual int socket_sendto(void* handle, const SocketAddress& address, const void* data, unsigned size);
    virtual int socket_recvfrom(void* handle, SocketAddress* address, void* buffer, unsigned size);
    virtual void socket_attach(void* handle, void (*callback)(void*), void* data);

    virtual int socket_open_tls(void** handle, nsapi_protocol_t proto, unsigned use_tls);
    virtual int socket_open_private(void** handle, nsapi_protocol_t proto, bool use_tls);
    virtual int find_free_socket();
    virtual WINC1500_socket* get_socket_by_id(int socket_id);

    virtual NetworkStack* get_stack() { return this; }

   private:
    friend class WINC1500TLSSocket;
    static WINC1500Interface* instance;

    Thread _wifi_thread;
    Semaphore _got_scan_result, _connected, _disconnected, _rssi_request;

    // socket related private variables
    Thread _socket_thread;
    Mutex _mutex;
    Semaphore _socket_connected, _socket_dns_resolved, _socket_data_sent, _socket_data_recv;

    struct WINC1500_socket _socker_arr[MAX_SOCKET];
    struct connection_info _ip_config;
    struct ap_connection_info _ap_config;

    bool _winc_debug;
    bool is_initialized;

    /** Output buffer for return string variables. */
    char output_buffer[20];
    /** Index of scan list to request scan result. */
    static uint8_t _scan_request_index;
    /** Number of APs found. */
    static uint8_t _num_found_ap;

    static nsapi_wifi_ap_t _found_ap_list[MAX_NUM_APs];

    char _ap_ssid[33]; /* 32 is what 802.11 defines as longest possible name; +1 for the \0 */
    tenuM2mSecType _ap_sec = M2M_WIFI_SEC_WPA_PSK;
    uint8_t _ap_ch = M2M_WIFI_CH_ALL;
    char _ap_pass[64]; /* The longest allowed passphrase */

    // todo:fix me: add this field to Winc1500 socket array
    struct sockaddr_in _current_sock_addr;

    uint16_t _received_data_size;

    union {
        uint32_t p32ip_addr;
        uint8_t p8ip_addr[NSAPI_IPv4_BYTES];
    } _resolved_DNS_addr;

    WINC1500Interface();
    WINC1500Interface(WINC1500Interface const&);  // Don't Implement.
    void operator=(WINC1500Interface const&);     // Don't implement

    void wifi_cb(uint8_t u8MsgType, void* pvMsg);
    static void winc1500_wifi_cb(uint8_t u8MsgType, void* pvMsg);
    static void wifi_thread_cb();

    static int winc1500_err_to_mn_err(int err);

    void socket_cb(SOCKET sock, uint8_t u8Msg, void* pvMsg);
    static void winc1500_socket_cb(SOCKET sock, uint8_t u8Msg, void* pvMsg);

    void dnsResolveCallback(uint8* pu8HostName, uint32 u32ServerIP);
    static void winc1500_dnsResolveCallback(uint8* pu8HostName, uint32 u32ServerIP);

    int request_socket_recv(WINC1500_socket* socket, void* input_buff_ptr, unsigned size);

    bool isInitialized();
    int winc_write_flash(const unsigned char *data, uint32 offset, unsigned int data_len, int chip_erase);

};

#endif
