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
SVNVStore* WINC1500Interface::_nvstore;

const char* ip_to_str(const uint32* ip_addr, char* buf, int len) {
    uint8* p8ip = (uint8*)ip_addr;
    snprintf(buf, len, "%u.%u.%u.%u", p8ip[0], p8ip[1], p8ip[2], p8ip[3]);
    return buf;
}

WINC1500Interface::WINC1500Interface(SVNVStore* nvstore) {
    // init sequence
    tstrWifiInitParam param;
    int8_t ret;
    uint8 mac_buffer[6];

    _winc_debug = _winc_debug || MBED_WINC1500_ENABLE_DEBUG;
    _nvstore = nvstore;
    /* Initialize the BSP. */

    is_initialized = true;

    nm_bsp_init();
    nm_drv_init_hold();
    uint8 u8Mode = M2M_WIFI_MODE_NORMAL;
    ret = wait_for_bootrom(u8Mode);
    if (M2M_SUCCESS != ret) {
        winc_debug(_winc_debug, "Error initialize bootrom \r\n");
    }
    wait(0.2);
    tstrM2mRev firm_info;
    nm_get_firmware_info(&firm_info);
    winc_debug(_winc_debug, "WINC firmware version: %d.%d.%d\r\n",
            firm_info.u8FirmwareMajor, firm_info.u8FirmwareMinor, firm_info.u8FirmwarePatch);
    uint16_t firm_version = M2M_MAKE_VERSION(firm_info.u8FirmwareMajor, firm_info.u8FirmwareMinor, firm_info.u8FirmwarePatch);
    uint16_t min_req_version = M2M_MAKE_VERSION(M2M_MIN_REQ_DRV_VERSION_MAJOR_NO, M2M_MIN_REQ_DRV_VERSION_MINOR_NO, M2M_MIN_REQ_DRV_VERSION_PATCH_NO);
    if ((firm_info.u8FirmwareMajor > WINC1500_MAX_MAJOR_VERSION) || (firm_version < min_req_version)) {
        winc_debug(_winc_debug, "WINC1500 FIRMWARE ERROR. Please, update firmware for winc1500");
        nm_bus_iface_deinit();
        nm_spi_deinit();
    } else {
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
    }
    if(_nvstore) {
        _nvstore->nv_store_get_mac(mac_buffer, 6);
        winc_debug(_winc_debug, "MAC address obtained: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                mac_buffer[0], mac_buffer[1], mac_buffer[2], mac_buffer[3], mac_buffer[4], mac_buffer[5]);
        m2m_wifi_set_mac_address(mac_buffer);
    }
    winc_debug(_winc_debug, "Starting winc..");

    /* Initialize socket module. */
    WINC_SOCKET(socketInit)();
    /* Register socket callback function. */
    WINC_SOCKET(registerSocketCallback)(winc1500_socket_cb, winc1500_dnsResolveCallback);

    _wifi_thread.start(callback(wifi_thread_cb));
}

WINC1500Interface& WINC1500Interface::getInstance(SVNVStore* nvstore) {
    static WINC1500Interface instance(nvstore);

    return instance;
}

WINC1500Interface& WINC1500Interface::getInstance() {

    return WINC1500Interface::getInstance(_nvstore);
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
    int rc = _nvstore->nv_store_set_mac(mac_buffer, sizeof(mac_buffer));
    if (rc) {
        winc_debug(_winc_debug, "Can't write MAC to nv-store res: %d \r\n", rc);
    }
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

int WINC1500Interface::winc_flash_read(char *str, const char *addr, const char *num) {
    uint32 read_addr = atoi(addr);
    uint32 read_size = atoi(num);
    char *p_str = str;
    printf("SPI fl read - addr: 0x%x, size: 0x%x\r\n", read_addr, read_size);
    uint8 read_buf[32];
    if(read_size > 32) {
        printf("Data size too big, res: %d\r\n", M2M_ERR_INVALID_ARG);
        return M2M_ERR_INVALID_ARG;
    }
    if(spi_flash_read(read_buf, read_addr, read_size) != M2M_SUCCESS) {
        printf("Data read error\r\n");
        return M2M_SPI_FAIL;
    }
    printf("%d %d %d %d\r\n", read_buf[1], read_buf[3], read_buf[4], read_buf[5]);
    for(int i=0;i<read_size;i++) {
        sprintf(p_str,"%02x ", read_buf[i]);
        p_str+=3;
        if(((i+1) % 16) == 0) {
            sprintf(p_str,"\r\n");
            p_str+=2;
        }
    }
    *p_str = 0;
    return M2M_SUCCESS;
}

int WINC1500Interface::winc_write_flash(const unsigned char *data, uint32 offset, unsigned int data_len, int chip_erase) {
    int ret;
    uint32 erase_size = data_len;
    if(chip_erase) {
        erase_size = (spi_flash_get_size() * 1024 *1024) / 8;
    }
    printf("Erasing chip, size: %d bytes at offset 0x%08x\r\n", erase_size, offset);
    if (spi_flash_erase(offset, erase_size) != M2M_SUCCESS) {
        printf("Chip erase failed!!\r\n");
        return M2M_ERR_FAIL;
    }
    printf("Start write flash\r\n");
    ret = spi_flash_write((uint8 *)data, offset, data_len);
    if (ret != M2M_SUCCESS)
        printf("Flash write failed! Res: %d\r\n", ret);
    else
        printf("Flash write completed!\r\n");
    return ret;
}

int WINC1500Interface::winc_write_chip(const unsigned char *data, unsigned int data_len) {
    return winc_write_flash(data, 0, data_len, 1);
}

int WINC1500Interface::winc_write_ota(const unsigned char *data, unsigned int data_len) {
    return winc_write_flash(data + 40, M2M_OTA_IMAGE2_OFFSET, data_len - 40, 0);
}

int WINC1500Interface::winc_download_mode(void){
    uint32 flashTotalSize;
    int ret = m2m_wifi_download_mode();
    if(M2M_SUCCESS != ret)
    {
        printf("Unable to enter download mode\r\n");
    }
    else
    {
        flashTotalSize = (spi_flash_get_size() * 1024 *1024) / 8;
        printf("Download mode is ready, flash size: %d bytes\r\n", flashTotalSize);
    }
    return ret;
}

int WINC1500Interface::winc_get_version(char *str, int len){
    tstrM2mRev firm_info;
    tstrM2mRev ota_firm_info;
    nm_get_firmware_info(&firm_info);
    nm_get_ota_firmware_info(&ota_firm_info);
    snprintf(str, len, "Main firm: %d.%d.%d, drv: %d.%d.%d, chip: 0x%x, Date: %s\r\n"
            "OTA firm: %d.%d.%d, drv: %d.%d.%d, chip: 0x%x, Date: %s\r\n",
            firm_info.u8FirmwareMajor, firm_info.u8FirmwareMinor, firm_info.u8FirmwarePatch,
            firm_info.u8DriverMajor, firm_info.u8DriverMinor, firm_info.u8DriverPatch, firm_info.u32Chipid, firm_info.BuildDate,
            ota_firm_info.u8FirmwareMajor, ota_firm_info.u8FirmwareMinor, ota_firm_info.u8FirmwarePatch,
            ota_firm_info.u8DriverMajor, ota_firm_info.u8DriverMinor, ota_firm_info.u8DriverPatch, ota_firm_info.u32Chipid, ota_firm_info.BuildDate);
    return M2M_SUCCESS;
}

int WINC1500Interface::winc_chip_erase(void){
    uint32 flashTotalSize;
    flashTotalSize = (spi_flash_get_size() * 1024 *1024) / 8;
    printf("Erasing chip, size: %d bytes\r\n", flashTotalSize);
    if (spi_flash_erase(0, flashTotalSize) != M2M_SUCCESS) {
        printf("Chip erase failed!!\r\n", flashTotalSize);
        return M2M_ERR_FAIL;
    }
    printf("Chip erase completed!\r\n");
    return M2M_SUCCESS;
}

int WINC1500Interface::winc_switch_part(void) {
    int ret;
    ret = m2m_ota_switch_firmware();
    printf("Switching complete, result: %d bytes\r\n", ret);
    return ret;
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
    winc_debug(_winc_debug, "WINC1500Interface::socket_open");
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

    winc_debug(_winc_debug, "socket->tls =%i\n", (int)socket->tls);

    int idx = WINC_SOCKET(socket)(AF_INET, SOCK_STREAM, socket->tls);

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

    winc_debug(_winc_debug, "Socket_connect");

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

int WINC1500Interface::request_socket_recv(WINC1500_socket* socket, void* input_buff_ptr, unsigned size) {
    
    //init recv fucntion one more time 
    sint16 err = WINC_SOCKET(recv)(socket->id, (void*)socket->input_buff_pos, (uint16_t)size, 100);

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
        // winc_debug(_winc_debug, "Recv data size: %i", sizeof(data));

        return socket->received_data_size; //to do: fix recv function
    }
}

int WINC1500Interface::socket_recv(void* handle, void* data, unsigned size) {
    ScopedLock<Mutex> lock(_mutex);

    struct WINC1500_socket* socket = (struct WINC1500_socket*)handle;

    if (!socket->connected) {
        _mutex.unlock();
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    int ptr_diff = (int)(socket->input_buff_pos - socket->read_out_pos);

    //if there is not enough data
    if (ptr_diff < size) {

        if(ptr_diff == 0) {
            //no data left->flush input buffer 
            memset(socket->input_buff, 0, sizeof(socket->input_buff));
            //reset ptr pos
            socket->input_buff_pos = &socket->input_buff[0];
            socket->read_out_pos = &socket->input_buff[0];

            socket->received_data_size = 0;

            request_socket_recv(socket, socket->input_buff_pos, size);
        }
        else if (ptr_diff > 0) {
            
            int bytes_to_delete = (int)(socket->read_out_pos - &socket->input_buff[0]);
            int bytes_to_copy = (int)(&socket->input_buff[sizeof(socket->input_buff)-1]-socket->read_out_pos);

            memset(socket->input_buff, 0, bytes_to_delete);
            memmove(socket->input_buff, socket->read_out_pos, bytes_to_copy);

            socket->read_out_pos -= bytes_to_delete;
            socket->input_buff_pos -= bytes_to_delete;

            request_socket_recv(socket, socket->input_buff_pos, size);
        }
        else {
            winc_debug(_winc_debug, "pointer is lost: %i", ptr_diff);
            return NSAPI_ERROR_DEVICE_ERROR;
        }   
    }

    //continue to dump data
    memmove(data, socket->read_out_pos, size);
    //change pointer pos
    socket->read_out_pos += size;        
            
    return size;
    
    // else

    

    // while(((uint8_t)input_buff_pos - read_out_pos) < size && ptr_diff <= 0)
    // {
        

    //     //init recv fucntion one more time 
    //     sint16 err = WINC_SOCKET(recv)(socket->id, (void*)input_buff_pos, (uint16_t)size, 100);

    //     if (err != SOCK_ERR_NO_ERROR) {
    //         winc_debug(_winc_debug, "Error requesting receive. err_code = %i", err);
    //         return NSAPI_ERROR_DEVICE_ERROR;
    //     } else {
    //         winc_debug(_winc_debug, "Successfully requested recv");

    //         uint32_t tok = _socket_data_recv.wait(WINC1500_RECV_TIMEOUT);
    //         if (!tok) {
    //             winc_debug(_winc_debug, "Socket recv timeout!");
    //             return NSAPI_ERROR_TIMEOUT;
    //         }

    //         winc_debug(_winc_debug, "Recv semaphore released!");
    //         winc_debug(_winc_debug, "Recv data size: %i", sizeof(data));

    //         return _received_data_size; //to do: fix recv function
    //     }
    // }

    // uint8_t ptr_diff = (uint8_t)input_buff_pos - read_out_pos;
    
    // if(ptr_diff > size) {
    //     //continue to dump data
    //     memcpy(data, socket->input_buff_pos, size);
    //     //change pointer pos
    //     read_out_pos = (uint8_t*)(read_out_pos + size);        
        
    //     return size;
    // }
    // else {
    //     //no data left->flush input buffer 
    //     memset(socket->input_buff, 0, sizeof(socket->input_buff));
    //     //reset ptr pos
    //     socket->input_buff_pos = &input_buff;
    //     socket->read_out_pos = &input_buff;

    //     socket->received_data_size = 0;

    //     //init recv fucntion one more time 
    //     sint16 err = WINC_SOCKET(recv)(socket->id, (void*)input_buff_pos, (uint16_t)size, 100);

    //     if (err != SOCK_ERR_NO_ERROR) {
    //         winc_debug(_winc_debug, "Error requesting receive. err_code = %i", err);
    //         return NSAPI_ERROR_DEVICE_ERROR;
    //     } else {
    //         winc_debug(_winc_debug, "Successfully requested recv");

    //         uint32_t tok = _socket_data_recv.wait(WINC1500_RECV_TIMEOUT);
    //         if (!tok) {
    //             winc_debug(_winc_debug, "Socket recv timeout!");
    //             return NSAPI_ERROR_TIMEOUT;
    //         }

    //         winc_debug(_winc_debug, "Recv semaphore released!");
    //         winc_debug(_winc_debug, "Recv data size: %i", sizeof(data));

    //         return _received_data_size; //to do: fix recv function
    //     }
    // }

    // winc_debug(_winc_debug, "socket_id = %i", socket->id);
    // winc_debug(_winc_debug, "amount of data to receive = %i", size);

    
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
            printf_all("[%d] SSID:%s\r\n", _scan_request_index, pstrScanResult->au8SSID);

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
            printf_all("Wi-Fi connected\r\n");
            printf_all("Wi-Fi IP is %s\r\n", ip_to_str(&_ip_config.u32IP, output_buffer, sizeof(output_buffer)));

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
                //todo: add close socket if connection failed
            }

            break;

        case SOCKET_MSG_RECV:

            pstrRecvMsg = (tstrSocketRecvMsg*)pvMsg;

             if ((pstrRecvMsg->pu8Buffer != NULL) && (pstrRecvMsg->s16BufferSize > 0)) {
                //find the appropriate socket
                struct WINC1500_socket* socket = &_socker_arr[sock];

                //copy received data to socket buffer
                memcpy(socket->input_buff_pos, pstrRecvMsg->pu8Buffer, pstrRecvMsg->s16BufferSize);
                //shift pointer
                socket->input_buff_pos += pstrRecvMsg->s16BufferSize;
                socket->received_data_size += pstrRecvMsg->s16BufferSize;

                winc_debug(_winc_debug, "Received some data!");
                winc_debug(_winc_debug, "Received data: (%.*s)", pstrRecvMsg->s16BufferSize, (char *)pstrRecvMsg->pu8Buffer);
                winc_debug(_winc_debug, "Data size: %i", pstrRecvMsg->s16BufferSize);
                winc_debug(_winc_debug, "remaining data size: %i", pstrRecvMsg->u16RemainingSize);

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