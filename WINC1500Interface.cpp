#include "WINC1500Interface.h"
#include "TCPSocket.h"
#include "ScopedLock.h"

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
    _wifi_thread.start(callback(wifi_thread_cb));
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
    if (!isInitialized()) {
        winc_debug(_winc_debug, "Winc1500 Interface is not initialized. Please, initialize it first...");
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    return socket_open_private(handle, proto, true);
}

int WINC1500Interface::socket_open(void** handle, nsapi_protocol_t proto) {
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

int WINC1500Interface::socket_open_private(void** handle, nsapi_protocol_t proto, bool use_tls) {
    ScopedLock<Mutex> lock(_mutex);

    /* Initialize socket module. */
    WINC_SOCKET(socketInit)();
    /* Register socket callback function. */
    WINC_SOCKET(registerSocketCallback)(winc1500_socket_cb, winc1500_dnsResolveCallback);

    int idx = WINC_SOCKET(socket)(AF_INET, SOCK_STREAM, use_tls);

    if (idx >= 0) {
	
	struct WINC1500_socket* socket = &_socker_arr[idx];

	if (!socket) {
		winc_debug(_winc_debug, "pointer to socket is NULL");
		return NSAPI_ERROR_NO_SOCKET;
	}
	socket->id = idx;

        winc_debug(_winc_debug, "WINC1500Interface: socket_opened, id=%d\n", socket->id);

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

        socket->addr = 0;
        socket->read_data_size = 0;
        socket->proto = proto;
        socket->connected = false;
        *handle = socket;
    }

    if (idx < 0) {
        winc_debug(_winc_debug, "socket creating failure!");
        return NSAPI_ERROR_NO_SOCKET;
    } else {
        return NSAPI_ERROR_OK;
    }
}

int WINC1500Interface::socket_close(void* handle) {
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
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_listen(void* handle, int backlog) {
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

int WINC1500Interface::socket_connect(void* handle, const SocketAddress& addr) {
    ScopedLock<Mutex> lock(_mutex);

    winc_debug(_winc_debug, "Socket_connect");

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    _current_sock_addr.sin_family = AF_INET;
    _current_sock_addr.sin_port = _htons(socket->port);

    winc_debug(_winc_debug, "WINC1500_IP address bytes: %x\n", (unsigned int)_current_sock_addr.sin_addr.s_addr);

    int rc = WINC_SOCKET(connect)(socket->id, (struct sockaddr*)&_current_sock_addr, sizeof(_current_sock_addr));

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

    return rc;
}

int WINC1500Interface::socket_accept(void* server, void** socket, SocketAddress* addr) {
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_send(void* handle, const void* data, unsigned size) {
    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    winc_debug(_winc_debug, "socket_send entry point\n");
    winc_debug(_winc_debug, "Socket ID: %i\n", socket->id);
    winc_debug(_winc_debug, "Data to send: %s\n", (char*)data);
    winc_debug(_winc_debug, "Data size: %i\n", size);
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

    return size;
}

int WINC1500Interface::socket_recv(void* handle, void* data, unsigned size) {
    ScopedLock<Mutex> lock(_mutex);

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    if (!socket->connected) {
        _mutex.unlock();
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    winc_debug(_winc_debug, "socket_id = %i", socket->id);
    winc_debug(_winc_debug, "amount of data to receive = %i", size);

    sint16 err = WINC_SOCKET(recv)(socket->id, (void*)data, (uint16)size, 100);
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
        winc_debug(_winc_debug, "Recv data size: %i", sizeof(data));

        return _received_data_size;
    }
}

int WINC1500Interface::socket_sendto(void* handle, const SocketAddress& addr, const void* data, unsigned size) {
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_recvfrom(void* handle, SocketAddress* addr, void* data, unsigned size) {
    return NSAPI_ERROR_UNSUPPORTED;
}

void WINC1500Interface::socket_attach(void* handle, void (*cb)(void*), void* data) {}

void WINC1500Interface::winc1500_wifi_cb(uint8_t u8MsgType, void* pvMsg) {
    getInstance().wifi_cb(u8MsgType, pvMsg);
}

void WINC1500Interface::wifi_cb(uint8_t u8MsgType, void* pvMsg) {
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
            }

            break;

        case SOCKET_MSG_RECV:

            pstrRecvMsg = (tstrSocketRecvMsg*)pvMsg;

            if ((pstrRecvMsg->pu8Buffer != NULL) && (pstrRecvMsg->s16BufferSize > 0)) {
                winc_debug(_winc_debug, "Received some data!");
                winc_debug(_winc_debug, "Data size: %i", pstrRecvMsg->s16BufferSize);
                winc_debug(_winc_debug, "remaining data size: %i", pstrRecvMsg->u16RemainingSize);

                _received_data_size = pstrRecvMsg->s16BufferSize;

                if (pstrRecvMsg->u16RemainingSize != 0) {
                    winc_debug(_winc_debug, "Some data left [%i], waiting...", pstrRecvMsg->u16RemainingSize);
                } else {
                    winc_debug(_winc_debug, "All data received!");
                    _socket_data_recv.release();
                }
            }

            break;
        case SOCKET_MSG_SEND:

            winc_debug(_winc_debug, "Some data was sent!");

            send_ret = *(int16_t*)pvMsg;
            winc_debug(_winc_debug, "pvMSG: %i", send_ret);

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
        _current_sock_addr.sin_addr.s_addr = u32ServerIP;
        _socket_dns_resolved.release();
    } else {
        winc_debug(_winc_debug, "Got NULL resolve address!");
    }
}
