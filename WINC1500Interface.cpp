#include "WINC1500Interface.h"
#include "TCPSocket.h"
#include "ScopedLock.h"
#include "sockets.h"
#include "ip4_addr.h"

#define inet_pton(af,src,dst)   ip4addr_aton((src),(ip4_addr_t*)(dst))

#define BYTE_SWAP(num) ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);

uint8_t WINC1500Interface::_scan_request_index;
/** Number of APs found. */
uint8_t WINC1500Interface::_num_found_ap;

nsapi_wifi_ap_t WINC1500Interface::_found_ap_list[MAX_NUM_APs];

const char* ip_to_str(const uint32* ip_addr, char* buf, int len) {
    uint8* p8ip = (uint8*)ip_addr;
    snprintf(buf, len, "%u.%u.%u.%u", p8ip[0], p8ip[1], p8ip[2], p8ip[3]);
    return buf;
}

WINC1500Interface::WINC1500Interface() {
    // init sequence
    tstrWifiInitParam param;
    int8_t ret;

    _winc_debug = _winc_debug || MBED_WINC1500_ENABLE_DEBUG;

    /* Initialize the BSP. */

    is_initialized = true;

    nm_bsp_init();

    /* Initialize Wi-Fi driver with data and status callbacks. */
    param.pfAppWifiCb = winc1500_wifi_cb;
    ret = m2m_wifi_init(&param);
    if (M2M_SUCCESS != ret) {
        is_initialized = false;
        switch (ret) {
            case M2M_ERR_FIRMWARE:
                winc_debug(_winc_debug, "M2M_ERR_FIRMWARE. Please, update firmware on winc1500");
            case M2M_ERR_FAIL:
                winc_debug(_winc_debug, "M2M_ERR_FAIL. Opps, smth failed..");
        }
    }

    winc_debug(_winc_debug, "Starting winc..");

    /* Initialize socket module. */
    WINC_SOCKET(socketInit)();
    /* Register socket callback function. */
    WINC_SOCKET(registerSocketCallback)(winc1500_socket_cb, winc1500_dnsResolveCallback);

    _wifi_thread.start(callback(wifi_thread_cb));
    _recv_thread.start(callback(winc1500_recv_thread_cb));
}

WINC1500Interface& WINC1500Interface::getInstance() {
    static WINC1500Interface instance;

    return instance;
}

bool WINC1500Interface::isInitialized() {
    return is_initialized;
}

int WINC1500Interface::connect(const char* ssid, const char* pass, nsapi_security_t security, uint8_t channel) {
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    set_credentials(ssid, pass, security);
    set_channel(channel);

    return connect();
}

int WINC1500Interface::connect() {
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    sint8 ret = m2m_wifi_connect((char*)_ap_ssid, strlen(_ap_ssid), _ap_sec, (void*)_ap_pass, _ap_ch);

    uint32_t tok = _connected.wait(WINC1500_CONNECT_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "Connection timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }

    if (ret != M2M_SUCCESS) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    // wait for connected semaphore realease
    return NSAPI_ERROR_OK;
}

nsapi_error_t WINC1500Interface::gethostbyname(const char* name, SocketAddress* address, nsapi_version_t version) {
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    ScopedLock<Mutex> lock(_mutex);

    winc_debug(_winc_debug, "WINC1500Interface::gethostbyname entry point");
    winc_debug(_winc_debug, "address name: %s", name);

    if (address->set_ip_address(name)) {
        winc_debug(_winc_debug, "IPbytes: %s", (uint8_t*)address->get_ip_address());

        if (version != NSAPI_UNSPEC && address->get_ip_version() != version) {
            return NSAPI_ERROR_DNS_FAILURE;
        }

        return NSAPI_ERROR_OK;
    }

    sint8 s8Err = WINC_SOCKET(gethostbyname)((uint8_t*)name);

    if (s8Err != 0) {
        winc_debug(_winc_debug, "Error occurred during DNC resolve. err_code = %i", s8Err);

        return NSAPI_ERROR_DNS_FAILURE;
    } else {
        winc_debug(_winc_debug, "DNS request passed OK");
    }

    uint32_t tok = _socket_dns_resolved.wait(WINC1500_DNS_RESOLVE_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "DNS resolve timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }

    char ip32_addr[NSAPI_IP_SIZE];
    ip_to_str(&_resolved_DNS_addr.p32ip_addr, ip32_addr, sizeof(ip32_addr));
    // *ip32_addr = ip_to_str(&_resolved_DNS_addr.p32ip_addr, output_buffer, sizeof(output_buffer));

    winc_debug(_winc_debug, "IP address is: %s", ip32_addr);

    address->set_ip_address(ip32_addr);

    return NSAPI_ERROR_OK;
}

int WINC1500Interface::set_credentials(const char* ssid, const char* pass, nsapi_security_t security) {
    ScopedLock<Mutex> lock(_mutex);

    memset(_ap_ssid, 0, sizeof(_ap_ssid));
    strncpy(_ap_ssid, ssid, sizeof(_ap_ssid) - 1);

    memset(_ap_pass, 0, sizeof(_ap_pass));
    strncpy(_ap_pass, pass, sizeof(_ap_pass) - 1);

    switch (security) {
        case NSAPI_SECURITY_NONE:
            _ap_sec = M2M_WIFI_SEC_OPEN;
            break;
        case NSAPI_SECURITY_WEP:
            _ap_sec = M2M_WIFI_SEC_WEP;
            break;
        case NSAPI_SECURITY_WPA_WPA2:
            _ap_sec = M2M_WIFI_SEC_WPA_PSK;
            break;
        default:
            _ap_sec = M2M_WIFI_SEC_INVALID;
            break;
    }

    return 0;
}

int WINC1500Interface::set_channel(uint8_t channel) {
    _ap_ch = channel;
    return NSAPI_ERROR_OK;
}

int WINC1500Interface::disconnect() {
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    ScopedLock<Mutex> lock(_mutex);

    m2m_wifi_disconnect();

    uint32_t tok = _disconnected.wait(WINC1500_DISCONNECT_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "Disconnect timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }

    return NSAPI_ERROR_OK;
}

const char* WINC1500Interface::get_ip_address() {
    return ip_to_str(&_ip_config.u32IP, output_buffer, sizeof(output_buffer));
}

const char* WINC1500Interface::get_mac_address() {
    uint8 mac_buffer[6];
    if (m2m_wifi_get_mac_address(mac_buffer) != M2M_SUCCESS)
        return "ERROR";
    snprintf(output_buffer, sizeof(output_buffer), "%02X:%02X:%02X:%02X:%02X:%02X", mac_buffer[0], mac_buffer[1],
             mac_buffer[2], mac_buffer[3], mac_buffer[4], mac_buffer[5]);
    return (const char*)&output_buffer;
}

const char* WINC1500Interface::get_otp_mac_address() {
    uint8 mac_is_valid, mac_buffer[6];
    if (m2m_wifi_get_otp_mac_address(mac_buffer, &mac_is_valid) != M2M_SUCCESS)
        return "ERROR";
    snprintf(output_buffer, sizeof(output_buffer), "%02X:%02X:%02X:%02X:%02X:%02X", mac_buffer[0], mac_buffer[1],
             mac_buffer[2], mac_buffer[3], mac_buffer[4], mac_buffer[5]);
    return (const char*)&output_buffer;
}

int WINC1500Interface::set_mac_address(const uint8* mac_address) {
    uint8 mac_buffer[6];
    memcpy(mac_buffer, mac_address, 6);
    return m2m_wifi_set_mac_address(mac_buffer);
}

const char* WINC1500Interface::get_gateway() {
    return ip_to_str(&_ip_config.u32Gateway, output_buffer, sizeof(output_buffer));
}

const char* WINC1500Interface::get_netmask() {
    return ip_to_str(&_ip_config.u32SubnetMask, output_buffer, sizeof(output_buffer));
}

int8_t WINC1500Interface::get_rssi() {
    if (m2m_wifi_req_curr_rssi() != M2M_SUCCESS) {
        winc_debug(_winc_debug, "RSSI request timeout!");
        return 1;
    }
    uint32_t tok = _rssi_request.wait(WINC1500_SEND_TIMEOUT);
    if (!tok) {
        return 1;
    }
    return _ip_config.rssi;
}

int WINC1500Interface::scan(WiFiAccessPoint* res, unsigned count) {
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    m2m_wifi_request_scan(M2M_WIFI_CH_ALL);

    uint32_t tok = _got_scan_result.wait(WINC1500_SCAN_RESULT_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "Scan result timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }

    for (uint8_t i = 0; i < _num_found_ap; i++) {
        res[i] = (WiFiAccessPoint)_found_ap_list[i];
    }

    return _num_found_ap;
}

/**********************SOCKET**************************/

int WINC1500Interface::socket_open_tls(void** handle, nsapi_protocol_t proto, unsigned use_tls) {
    winc_debug(_winc_debug, "WINC1500Interface::socket_open_tls");
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    return socket_open_private(handle, proto, true);
}

int WINC1500Interface::socket_open(void** handle, nsapi_protocol_t proto) {
    printf("WINC1500Interface::socket_open\n");
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    return socket_open_private(handle, proto, false);
}

int WINC1500Interface::find_free_socket() {
    // Look for an unused socket
    int id = -1;

    for (int i = 0; i < MAX_SOCKET; i++) {
        if (!_ids[i]) {
            id = i;
            _ids[i] = true;
            break;
        }
    }

    if (id == -1) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    return id;
}

int WINC1500Interface::socket_open_private(void** handle, nsapi_protocol_t proto, bool use_tls=false) {
    ScopedLock<Mutex> lock(_mutex);

    int socket_id = find_free_socket();
    if (socket_id == NSAPI_ERROR_NO_SOCKET) {
        // report error no free socket
        winc_debug(_winc_debug, "No free socket!");
    }

    struct WINC1500_socket* socket = &_socker_arr[socket_id];

    if (!socket) {
        winc_debug(_winc_debug, "pointer to socket is NULL");
        return NSAPI_ERROR_NO_SOCKET;
    }

    socket->tls = use_tls;
    if (!use_tls) {
        // WINC1500 needs for HTTP connection
        socket->tls = 0;
        socket->port = 80;
    } else {
        // WINC1500 needs for HTTPS connection
        socket->tls = 1;
        socket->port = 443;
    }

    /* Initialize socket module. */
    //WINC_SOCKET(socketInit)();
    /* Register socket callback function. */
    //WINC_SOCKET(registerSocketCallback)(winc1500_socket_cb, winc1500_dnsResolveCallback);

    winc_debug(_winc_debug, "socket->tls =%i\n", (int)socket->tls);

    int idx = WINC_SOCKET(socket)(AF_INET, SOCK_STREAM, socket->tls);

    if (idx >= 0) {
        socket->id = socket_id;
        winc_debug(_winc_debug, "WINC1500Interface: socket_opened, id=%d\n", socket->id);

        socket->addr = 0;
        socket->received_data_size = 0;
        socket->proto = proto;
        socket->connected = false;
        *handle = socket;
    }

    if (idx < 0) {
        winc_debug(_winc_debug, "socket creating failure!");
        return NSAPI_ERROR_NO_SOCKET;
    } 
    return NSAPI_ERROR_OK;
}

int WINC1500Interface::socket_close(void* handle) {
    printf("WINC1500Interface::socket_close\n");
    ScopedLock<Mutex> lock(_mutex);

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;
    winc_debug(_winc_debug, "WINC1500_socket: socket_close, id=%d\n", socket->id);

    sint8 err_code = WINC_SOCKET(close)(socket->id);
    if (err_code != SOCK_ERR_NO_ERROR) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    socket->connected = false;
    _ids[socket->id] = false;
    _socket_obj[socket->id] = 0;

    return NSAPI_ERROR_OK;
}

int WINC1500Interface::socket_bind(void* handle, const SocketAddress& address) {
    printf("WINC1500Interface::socket_bind\n");
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_listen(void* handle, int backlog) {
    printf("WINC1500Interface::socket_listen\n");
    return NSAPI_ERROR_UNSUPPORTED;
}

int winc1500_err_to_nsapi_err(int err) {
    switch (err) {
        case SOCK_ERR_NO_ERROR:
            return NSAPI_ERROR_OK;
        case SOCK_ERR_INVALID_ADDRESS:
            return NSAPI_ERROR_NO_ADDRESS;
        case SOCK_ERR_ADDR_ALREADY_IN_USE:
            return NSAPI_ERROR_ADDRESS_IN_USE;
        case SOCK_ERR_MAX_TCP_SOCK:
        case SOCK_ERR_MAX_UDP_SOCK:
            return NSAPI_ERROR_NO_MEMORY;
        case SOCK_ERR_INVALID_ARG:
            return NSAPI_ERROR_PARAMETER;
        case SOCK_ERR_MAX_LISTEN_SOCK:
            return NSAPI_ERROR_NO_SOCKET;
        case SOCK_ERR_INVALID:
            return NSAPI_ERROR_UNSUPPORTED;
        case SOCK_ERR_ADDR_IS_REQUIRED:
            return NSAPI_ERROR_NO_ADDRESS;
        case SOCK_ERR_CONN_ABORTED:
            return NSAPI_ERROR_CONNECTION_LOST;
        case SOCK_ERR_TIMEOUT:
            return NSAPI_ERROR_CONNECTION_TIMEOUT;
        case SOCK_ERR_BUFFER_FULL:
            return NSAPI_ERROR_NO_MEMORY;
        default:
            return NSAPI_ERROR_UNSUPPORTED;
    }
}

/* Convert the character string in "ip" into an unsigned integer.

   This assumes that an unsigned integer contains at least 32 bits. */

uint32_t ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return 0;
            }
        }
        if (n >= 256) {
            return 0;
        }
        v *= 256;
        v += n;
    }
    return (uint32_t)v;
}

int WINC1500Interface::socket_connect(void* handle, const SocketAddress& addr) {
    ScopedLock<Mutex> lock(_mutex);

    printf("WINC1500Interface::socket_connect\n");

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    struct sockaddr_in _current_sock;

    _current_sock.sin_family = AF_INET;
    _current_sock.sin_port = _htons(addr.get_port());
    
    uint32_t got_addr = BYTE_SWAP(ip_to_int(addr.get_ip_address()));
    winc_debug(_winc_debug, "WINC1500_IP address bytes: %x\n", got_addr);
    _current_sock.sin_addr.s_addr = got_addr;


    winc_debug(_winc_debug, "Socket id: %x\n", socket->id);
    winc_debug(_winc_debug, "Got address: %s\n", addr.get_ip_address());
    winc_debug(_winc_debug, "Got port: %u\n", addr.get_port());

    winc_debug(_winc_debug, "WINC1500_IP address bytes: %x\n", (unsigned int)_current_sock.sin_addr.s_addr);
    winc_debug(_winc_debug, "_current_sock_addr.sin_port: %x\n", _current_sock.sin_port);

    int rc = WINC_SOCKET(connect)(socket->id, (struct sockaddr*)&_current_sock, sizeof(struct sockaddr));

    winc_debug(_winc_debug, "rc = %i\n", rc);
    winc_debug(_winc_debug, "Waiting for semaphore release...");

    uint32_t tok = _socket_connected.wait(WINC1500_CONNECT_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "Socket connect timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }

    _ids[socket->id] = true;
    _socket_obj[socket->id] = socket;
    socket->connected = true;

    //requesting recv
    request_socket_recv(socket, socket->chunk_buff, sizeof(socket->chunk_buff));

    return rc;
}

int WINC1500Interface::socket_accept(void* server, void** socket, SocketAddress* addr) {
    printf("WINC1500Interface::socket_accept\n");
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_send(void* handle, const void* data, unsigned size) {
    printf("WINC1500Interface::socket_send\n");
    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    winc_debug(_winc_debug, "socket_send entry point\n");
    winc_debug(true, "Socket ID: %i\n", socket->id);
    winc_debug(_winc_debug, "Data to send: %s\n", (char*)data);
    winc_debug(true, "Data size: %i\n", size);
    winc_debug(_winc_debug, "strlen: %i\n", strlen((char*)data));

    ScopedLock<Mutex> lock(_mutex);

    // send data
    sint16 s16Ret = WINC_SOCKET(send)(socket->id, (void*)data, size, 0);

    if (s16Ret != SOCK_ERR_NO_ERROR) {
        winc_debug(_winc_debug, "Error occured during socket_send, err_code = %i\n", s16Ret);

        return NSAPI_ERROR_UNSUPPORTED;
    }

    uint32_t tok = _socket_data_sent.wait(WINC1500_SEND_TIMEOUT);
    if (!tok) {
        winc_debug(_winc_debug, "Socket send timeout!");
        return NSAPI_ERROR_TIMEOUT;
    }
    winc_debug(_winc_debug, "Socket semaphore released!");

    return size;
}

int WINC1500Interface::request_socket_recv(WINC1500_socket* socket, void* input_buff_ptr, unsigned size) {
    
    //init recv fucntion one more time 
    sint16 err = WINC_SOCKET(recv)(socket->id, input_buff_ptr, (uint16_t)size, 100);

    if (err != SOCK_ERR_NO_ERROR) {
        winc_debug(_winc_debug, "Error requesting receive. err_code = %i", err);
        return NSAPI_ERROR_DEVICE_ERROR;
    } else {
        winc_debug(_winc_debug, "Successfully requested recv");

        uint32_t tok = _socket_data_recv.wait(WINC1500_RECV_TIMEOUT);
        if (!tok) {
            winc_debug(_winc_debug, "Socket recv timeout!");
            return NSAPI_ERROR_TIMEOUT;
        }

        winc_debug(_winc_debug, "Recv semaphore released!");
        winc_debug(_winc_debug, "Recv data size: %u", socket->received_data_size);
        // winc_debug(true, "Received data: (%.*s)", socket->received_data_size, &socket->input_buff[0]);
        // winc_debug(_winc_debug, "Here is the received data:\n");
        // if (_winc_debug) {
        //     for (int i = 0; i < socket->received_data_size; i++)
        //     {   
        //         printf("%02X ", socket->read_out_pos[i]);
        //     }
        //     printf("\n\n");
        // }

        return socket->received_data_size; //to do: fix recv function
    }
}

int WINC1500Interface::socket_recv(void* handle, void* data, unsigned size) {
    printf("WINC1500Interface::socket_recv\n");
    ScopedLock<Mutex> lock(_mutex);

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    if (!socket->connected) {
        _mutex.unlock();
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    while(socket->circ_buff.size() < size) {
        
        winc_debug(_winc_debug, "Not enough data to send to user: %i, needed: %i",socket->circ_buff.size(), size);
        winc_debug(true, "Requesting recv()");
        //try to acquire more data
        request_socket_recv(socket, socket->chunk_buff, sizeof(socket->chunk_buff));
    }

    winc_debug(_winc_debug, "There is enough data to send to user: %i, needed: %i",socket->circ_buff.size(), size);

    uint8_t* data_ptr = (uint8_t*)data;
    //pop data from the circular buffer to the user buffer
    for (uint16_t i=0; i<size; i++) {
        socket->circ_buff.pop(data_ptr[i]);
    }

    socket->received_data_size -= size;

    return size;
}

int WINC1500Interface::socket_sendto(void* handle, const SocketAddress& addr, const void* data, unsigned size) {
    printf("WINC1500Interface::socket_sendto\n");

    struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;

    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    if((strcmp(addr.get_ip_address(), "0.0.0.0") == 0) || !addr.get_port())  {
        return NSAPI_ERROR_DNS_FAILURE;
    }

    if (socket->connected && socket->addr != addr) {
        if (!close(socket->id)) {
            return NSAPI_ERROR_DEVICE_ERROR;
        }
        socket->connected = false;
    }

    if (!socket->connected) {
        int err = socket_connect(socket, addr);
        if (err < 0) {
            return err;
        }
        socket->addr = addr;
    }

    return socket_send(socket, data, size);
}

int WINC1500Interface::socket_recvfrom(void* handle, SocketAddress* addr, void* data, unsigned size) {
    printf("WINC1500Interface::socket_recvfrom\n");
    struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;

    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    int ret = socket_recv(socket, data, size);
    if (ret >= 0 && addr) {
        *addr = socket->addr;
    }

    return ret;
}

void WINC1500Interface::socket_attach(void* handle, void (*cb)(void*), void* data) {
    printf("WINC1500Interface::socket_attach\n");
    struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;
    _cbs[socket->id].callback = cb;
    _cbs[socket->id].data = data;
}

void WINC1500Interface::winc1500_wifi_cb(uint8_t u8MsgType, void* pvMsg) {
    getInstance().wifi_cb(u8MsgType, pvMsg);
}

void WINC1500Interface::wifi_cb(uint8_t u8MsgType, void* pvMsg) {

    printf("WINC1500Interface::wifi_cb : %u\n", u8MsgType);

    switch (u8MsgType) {
        case M2M_WIFI_RESP_SCAN_DONE: {
            tstrM2mScanDone* pstrInfo = (tstrM2mScanDone*)pvMsg;
            _scan_request_index = 0;

            if (pstrInfo->u8NumofCh >= 1) {
                m2m_wifi_req_scan_result(_scan_request_index);
                _scan_request_index++;
            }

            break;
        }

        case M2M_WIFI_RESP_SCAN_RESULT: {
            tstrM2mWifiscanResult* pstrScanResult = (tstrM2mWifiscanResult*)pvMsg;

            memcpy(&_found_ap_list[_scan_request_index], &pstrScanResult, sizeof(tstrM2mWifiscanResult));

            /* display found AP. */
            printf("[%d] SSID:%s\r\n", _scan_request_index, pstrScanResult->au8SSID);

            strncpy(_found_ap_list[_scan_request_index].ssid, (const char*)pstrScanResult->au8SSID, 33);
            _found_ap_list[_scan_request_index].rssi = pstrScanResult->s8rssi;
            _found_ap_list[_scan_request_index].security = (nsapi_security_t)pstrScanResult->u8AuthType;
            _found_ap_list[_scan_request_index].channel = pstrScanResult->u8ch;

            for (int i = 0; i < SSID_LEN; i++) {
                _found_ap_list[_scan_request_index].bssid[i] = pstrScanResult->au8BSSID[i];
            }

            _num_found_ap = m2m_wifi_get_num_ap_found();

            if (_scan_request_index < _num_found_ap) {
                m2m_wifi_req_scan_result(_scan_request_index);
                _scan_request_index++;
            } else {
                // release the semaphore
                _got_scan_result.release();
            }

            break; 
        }

        case M2M_WIFI_RESP_CON_STATE_CHANGED: {
            tstrM2mWifiStateChanged* pstrWifiState = (tstrM2mWifiStateChanged*)pvMsg;
            if (pstrWifiState->u8CurrState == M2M_WIFI_CONNECTED) {
                m2m_wifi_request_dhcp_client();

            } else if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED) {
                _ip_config.u32IP = 0;
                _ip_config.u32Gateway = 0;
                _ip_config.u32SubnetMask = 0;
                printf("M2M_WIFI_RESP_CON_STATE_CHANGED. DISCONENCTED\r\n");
                printf("Wi-Fi disconnected\r\n");
                _disconnected.release();
            }

            break;
        }

        case M2M_WIFI_REQ_CONN: {
            printf("M2M_WIFI_REQ_CONN");
            break;
        }

        case M2M_WIFI_REQ_DHCP_CONF: {
            tstrM2MIPConfig* pIPAddress = (tstrM2MIPConfig*)pvMsg;
            _ip_config.u32IP = pIPAddress->u32StaticIP;
            _ip_config.u32Gateway = pIPAddress->u32Gateway;
            _ip_config.u32SubnetMask = pIPAddress->u32SubnetMask;
            printf("Wi-Fi connected\r\n");
            printf("Wi-Fi IP is %s\r\n", ip_to_str(&_ip_config.u32IP, output_buffer, sizeof(output_buffer)));
            
            // release the connection semaphore
            _connected.release();

            break;
        }
        case M2M_WIFI_RESP_CURRENT_RSSI: {
            sint8* ptrssi = (sint8*)pvMsg;
            _ip_config.rssi = *ptrssi;
            _rssi_request.release();
        }
    }
}

void WINC1500Interface::winc1500_socket_cb(SOCKET sock, uint8_t u8Msg, void* pvMsg) {
    getInstance().socket_cb(sock, u8Msg, pvMsg);
}

void WINC1500Interface::socket_cb(SOCKET sock, uint8_t u8Msg, void* pvMsg) {
    winc_debug(_winc_debug, "socket_cb entry point");
    winc_debug(_winc_debug, "WINC1500Interface::socket_cb : %u\n", u8Msg);

    tstrSocketConnectMsg* pstrConnect;
    tstrSocketRecvMsg* pstrRecvMsg;
    int send_ret;

    switch (u8Msg) {
        case SOCKET_MSG_CONNECT:

            pstrConnect = (tstrSocketConnectMsg*)pvMsg;
 
            if (pstrConnect->s8Error == 0) {
                // no error
                winc_debug(_winc_debug, "Socket successfully connected!");
                _socket_connected.release();
            } else {
                winc_debug(_winc_debug, "Socket connect failed!");
                winc_debug(_winc_debug, "err_code = %i", (int)pstrConnect->s8Error);
                //todo: add close socket if connection failed
            }

            break;

        case SOCKET_MSG_RECV:

            pstrRecvMsg = (tstrSocketRecvMsg*)pvMsg;

            // for (int i = 0; i < MAX_SOCKET; i++) {
            //             if (_cbs[i].callback) {
            //                 _cbs[i].callback(_cbs[i].data);
            //             }
            //         }

            winc_debug(_winc_debug, "SOCKET_MSG_RECV");

             if ((pstrRecvMsg->pu8Buffer != NULL) && (pstrRecvMsg->s16BufferSize > 0)) {
                //find the appropriate socket
                struct WINC1500_socket* socket = &_socker_arr[sock];

                // CircularBuffer* buf = socket->circ_buff;
                uint8_t* current_val = pstrRecvMsg->pu8Buffer;

                //copy received data to socket buffer
                // memmove(socket->input_buff_pos, pstrRecvMsg->pu8Buffer, pstrRecvMsg->s16BufferSize);
                //shift pointer

                //copy from chunk to circular buffer if it's not full
                for(uint16_t i=0; i<pstrRecvMsg->s16BufferSize; i++) {
                    if (!socket->circ_buff.full()) {
                        socket->circ_buff.push(pstrRecvMsg->pu8Buffer[i]);
                    }
                    else {
                        winc_debug(_winc_debug, "Buffer is full, aborting...!");
                        break;
                    }
                }

                winc_debug(_winc_debug, "Buffer size:  %i!", sizeof(pstrRecvMsg->pu8Buffer));
                winc_debug(true, "Received data (%u) from socket: %i!", pstrRecvMsg->s16BufferSize, socket->id);
                winc_debug(_winc_debug, "Received data: (%.*s)", pstrRecvMsg->s16BufferSize, (char*)pstrRecvMsg->pu8Buffer);

                // winc_debug(_winc_debug, "Here is the received data:\n");
                // if (_winc_debug) {
                //     for (int i = 0; i < pstrRecvMsg->s16BufferSize; i++)
                //     {   
                //         printf("%02X ", socket->input_buff_pos[i]);
                //     }
                //     printf("\n\n");
                // }

                winc_debug(_winc_debug, "Data size: %i", pstrRecvMsg->s16BufferSize);
                winc_debug(_winc_debug, "remaining data size: %i", pstrRecvMsg->u16RemainingSize);

                // socket->input_buff_pos += pstrRecvMsg->s16BufferSize;
                socket->received_data_size += pstrRecvMsg->s16BufferSize;

                if (pstrRecvMsg->u16RemainingSize != 0) {
                    winc_debug(_winc_debug, "Some data left [%i], waiting...", pstrRecvMsg->u16RemainingSize);

                    // sint16 err = WINC_SOCKET(recv)(socket->id, (void*)socket->input_buff_pos, pstrRecvMsg->s16BufferSize, 100);
                    // if (err != SOCK_ERR_NO_ERROR) {
                    //     winc_debug(true, "Error requesting receive. err_code = %i", err);
                    // }

                } else {
                    winc_debug(_winc_debug, "All data received!");
                   
                    _socket_data_recv.release();
                }
            }

            break;
        case SOCKET_MSG_SEND:

            winc_debug(_winc_debug, "Some data was sent!");

            send_ret = *(int16_t*)pvMsg;
            winc_debug(true, "Some data was sent. pvMSG: %i", send_ret);

            if (send_ret < 0) {
                /* Send failed. */
                winc_debug(_winc_debug, "Socket error: %i", send_ret);

            } else {

                _socket_data_sent.release();
            }

            break;
    }
}

void WINC1500Interface::wifi_thread_cb() {
    while (1) {
        /* Handle pending events from network controller. */
        while (m2m_wifi_handle_events(NULL) != M2M_SUCCESS) {
            wait_ms(1);
        }
    }
}

void WINC1500Interface::winc1500_recv_thread_cb() {
    getInstance().recv_thread_cb();
}

void WINC1500Interface::recv_thread_cb() {
    while (1) {
        for (int i = 0; i < MAX_SOCKET; i++) {
            _mutex.lock();
            if (_socket_obj[i] != 0) {
                struct WINC1500_socket *socket = (struct WINC1500_socket *)_socket_obj[i];
                /* Check if there is something to read for this socket. But if it */
                /* has already been read : don't read again */
                if ((socket->connected) && (socket->received_data_size == 0) && _cbs[socket->id].callback) {
                    /* if no callback is set, no need to read ?*/

                    //init recv fucntion one more time 
                    sint16 err = WINC_SOCKET(recv)(socket->id, socket->chunk_buff, sizeof(socket->chunk_buff), 100);
                    if (err != SOCK_ERR_NO_ERROR) {
                        winc_debug(false, "Error requesting receive. err_code = %i", err);
                        // return NSAPI_ERROR_DEVICE_ERROR;
                    } else {
                        winc_debug(false, "Successfully requested recv");

                        uint32_t tok = _socket_data_recv.wait(WINC1500_RECV_TIMEOUT);
                        if (!tok) {
                            winc_debug(_winc_debug, "Socket recv timeout!");
                            // return NSAPI_ERROR_TIMEOUT;
                        }
                    }

                    if (socket->received_data_size < 0) {
                        /* Mark donw connection has been lost or closed */
                        winc_debug(_winc_debug, "WINC1500Interface socket_check_read: i %d closed\r\n", i);
                        socket->connected = false;
                    }
                    if (socket->received_data_size != 0) {
                        /* There is something to read in this socket*/
                        if (_cbs[socket->id].callback) {
                            _cbs[socket->id].callback(_cbs[socket->id].data);
                        }
                    }
                }
            }
            _mutex.unlock();
        }
    }
}


void WINC1500Interface::winc1500_dnsResolveCallback(uint8* pu8HostName, uint32 u32ServerIP) {
    getInstance().dnsResolveCallback(pu8HostName, u32ServerIP);
}

void WINC1500Interface::dnsResolveCallback(uint8* pu8HostName, uint32 u32ServerIP) {
    winc_debug(_winc_debug, "resolve_cb for IP address %s", pu8HostName);
    if (u32ServerIP != 0) {
        winc_debug(_winc_debug, "resolve_cb: %s IP address is %d.%d.%d.%d\r\n\r\n", pu8HostName,
                   (int)IPV4_BYTE(u32ServerIP, 0), (int)IPV4_BYTE(u32ServerIP, 1), (int)IPV4_BYTE(u32ServerIP, 2),
                   (int)IPV4_BYTE(u32ServerIP, 3));

        winc_debug(_winc_debug, "DNS resolved. serve IP: 0x%x", (unsigned int)u32ServerIP);
        _resolved_DNS_addr.p32ip_addr = u32ServerIP;
        _current_sock_addr.sin_addr.s_addr = u32ServerIP;
        _socket_dns_resolved.release();
    } else {
        winc_debug(_winc_debug, "Got NULL resolve address!");
    }
}

#if MBED_WINC1500_PROVIDE_DEFAULT

WiFiInterface *WiFiInterface::get_default_instance() {

    return &WINC1500Interface::getInstance();
}
#endif