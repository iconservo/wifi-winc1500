#include "WINC1500Interface.h"

#include "TCPSocket.h"


uint8_t WINC1500Interface::scan_request_index;
	/** Number of APs found. */
uint8_t WINC1500Interface::num_founded_ap;

nsapi_wifi_ap_t WINC1500Interface::found_ap_list[MAX_NUM_APs];
int  WINC1500Interface::read_data_size;



WINC1500Interface::WINC1500Interface()
{
	//init sequence
	tstrWifiInitParam param;
	int8_t ret;

	_winc_debug = _winc_debug || CONF_WINC_DEBUG;

	/* Initialize the BSP. */
	nm_bsp_init();

	/* Initialize Wi-Fi parameters structure. */
	memset((uint8_t *)&param, 0, sizeof(tstrWifiInitParam));

	/* Initialize Wi-Fi driver with data and status callbacks. */
	param.pfAppWifiCb = wifi_cb;
	ret = m2m_wifi_init(&param);
	if (M2M_SUCCESS != ret) {
		printf("main: m2m_wifi_init call error!(%d)\r\n", ret);
		while (1) {
		}
	}

	winc_debug(_winc_debug, "Starting winc..");
    wifi_thread.start(callback(wifi_thread_cb));

}

WINC1500Interface& WINC1500Interface::getInstance()
{
	static WINC1500Interface instance;

    return instance;
}


int WINC1500Interface::connect(const char *ssid, const char *pass, nsapi_security_t security,
                               uint8_t channel)
{

    set_credentials(ssid, pass, security);
    set_channel(channel);

    return connect();
}

int WINC1500Interface::connect()
{

	sint8 ret = m2m_wifi_connect((char *)ap_ssid, strlen(ap_ssid), ap_sec, (void *)ap_pass, ap_ch);

	connected.wait();

	if (ret != M2M_SUCCESS)
	{
		return NSAPI_ERROR_NO_CONNECTION;
	}
	else
	{
		//wait for connected semaphore realease
	    return NSAPI_ERROR_OK;
	}

}

nsapi_error_t WINC1500Interface::gethostbyname(const char *name, SocketAddress *address, nsapi_version_t version)
{

	winc_debug(_winc_debug, "WINC1500Interface::gethostbyname entry point");


	winc_debug(_winc_debug, "address name: %s", name);


	_mutex.lock();

	if (address->set_ip_address(name)) {
		winc_debug(_winc_debug, "IPbytes: %s", (uint8_t *)address->get_ip_address());

		if (version != NSAPI_UNSPEC && address->get_ip_version() != version) {
			_mutex.unlock();
			return NSAPI_ERROR_DNS_FAILURE;
		}

		_mutex.unlock();
		return NSAPI_ERROR_OK;
	}

	char *ipbuff = new char[NSAPI_IP_SIZE];
	int ret = 0;
//	_ism.setTimeout(ISM43362_CONNECT_TIMEOUT);

	sint8 s8Err = WINC_SOCKET(gethostbyname)((uint8_t *)name);

	if (s8Err != 0) {
		winc_debug(_winc_debug, "Error occurred during DNC resolve. err_code = %i", s8Err);
		return NSAPI_ERROR_DNS_FAILURE;
	}
	else {
		winc_debug(_winc_debug, "DNS request passed OK");

	}

	socket_dns_resolved.wait();

	address->set_ip_address(ipbuff);

	winc_debug(_winc_debug, "Semaphore released!");

	_mutex.unlock();

	delete[] ipbuff;

	return NSAPI_ERROR_OK;
}

int WINC1500Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
    _mutex.lock();

    memset(ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid, ssid, sizeof(ap_ssid)-1);

    memset(ap_pass, 0, sizeof(ap_pass));
    strncpy(ap_pass, pass, sizeof(ap_pass)-1);

    switch(security) {
        case NSAPI_SECURITY_NONE:
            ap_sec = M2M_WIFI_SEC_OPEN;
            break;
        case NSAPI_SECURITY_WEP:
            ap_sec = M2M_WIFI_SEC_WEP;
            break;
        case NSAPI_SECURITY_WPA_WPA2:
            ap_sec = M2M_WIFI_SEC_WPA_PSK;
            break;
        default:
            ap_sec = M2M_WIFI_SEC_INVALID;
            break;
    }

    _mutex.unlock();

    return 0;
}

int WINC1500Interface::set_channel(uint8_t channel)
{
    ap_ch = channel;
//    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::disconnect()
{
	m2m_wifi_disconnect();

	disconnected.wait();

    return NSAPI_ERROR_OK;
}

const char *WINC1500Interface::get_ip_address()
{
    return (char *) &IP_addr.ip_addr_32;
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

	m2m_wifi_request_scan(M2M_WIFI_CH_ALL);

	got_scan_result.wait();

//	print("Got %d APs")

//	printf("Number of found APs: %d\n", num_founded_ap);

	for(uint8_t i=0; i<num_founded_ap; i++)
	{
		res[i] = (WiFiAccessPoint) found_ap_list[i];
	}

    return num_founded_ap;
}

struct WINC1500Socket {
    int id;
};


/**********************SOCKET**************************/

int WINC1500Interface::socket_open(void **handle, nsapi_protocol_t proto)
{

	// Look for an unused socket
	int id = -1;
    int idx;

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

	_mutex.lock();
	struct WINC1500_socket *socket = new struct WINC1500_socket;
	if (!socket) {
		_mutex.unlock();
		return NSAPI_ERROR_NO_SOCKET;
	}

	/* Initialize socket module. */
	WINC_SOCKET(socketInit)();
	/* Register socket callback function. */
	WINC_SOCKET(registerSocketCallback)(socket_cb, dnsResolveCallback);


	idx = WINC_SOCKET(socket)(AF_INET, SOCK_STREAM, 0);
	if (idx >= 0) {
		socket->id = id;
		winc_debug(_winc_debug, "WINC1500Interface: socket_open, id=%d\n", socket->id);

		memset(socket->read_data, 0, sizeof(socket->read_data));

		socket->addr = 0;
		socket->read_data_size = 0;
		socket->proto = proto;
		socket->connected = false;
		*handle = socket;
	}
	_mutex.unlock();

	if (idx < 0 ) {
		return NSAPI_ERROR_NO_SOCKET;
	} else {
		return NSAPI_ERROR_OK;
	}

}

int WINC1500Interface::socket_close(void *handle)
{
	_mutex.lock();

	struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;
	winc_debug(_winc_debug, "WINC1500_socket: socket_close, id=%d\n", socket->id);

	int err = NSAPI_ERROR_OK;
//	_ism.setTimeout(ISM43362_MISC_TIMEOUT);

	//@todo: add clode sequence for socket
//	if (!WINC_SOCKET(close)(params)) {
//		err = NSAPI_ERROR_DEVICE_ERROR;
//	}

	socket->connected = false;
	_ids[socket->id] = false;
	_socket_obj[socket->id] = 0;
	_mutex.unlock();
	delete socket;

	return err;
}

int WINC1500Interface::socket_bind(void *handle, const SocketAddress &address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_listen(void *handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}


int winc1500_err_to_nsapi_err(int err)
{
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
//	return 0;
}

int WINC1500Interface::socket_connect(void *handle, const SocketAddress &addr)
{

	winc_debug(_winc_debug, "Socket_open");

	int rc;

	struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;

//	_ism.setTimeout(ISM43362_CONNECT_TIMEOUT);
	const char *proto = (socket->proto == NSAPI_UDP) ? "1" : "0";

//	if (!_ism.open(proto, socket->id, addr.get_ip_address(), addr.get_port())) {
//		return NSAPI_ERROR_DEVICE_ERROR;
//	}
//
//	return 0;

//	struct sockaddr_in sin;
////	struct winc1500_sock *ws = (struct winc1500_sock *)sock;
////	int rc;
////
////	rc = winc1500_mn_addr_to_addr((struct mn_sockaddr_in *)addr, &sin);
////
//	sin.sin_family = AF_INET;
////	sin->sin_port = msin->msin_port;
//	sin.sin_port = _htons(addr.get_port());
//
//	sin.sin_addr.s_addr = IP_addr.ip_addr_32;
//
//	struct sockaddr_in addr_in;
//
//	addr_in.sin_family = AF_INET;
//	addr_in.sin_port = _htons(80);
//	addr_in.sin_addr.s_addr = IP_addr.ip_addr_32;


	current_sock_addr.sin_family = AF_INET;
	current_sock_addr.sin_port = _htons(80);

//	winc_debug(_winc_debug, "WINC1500_IP address: %s\n",  addr.get_ip_address());
	winc_debug(_winc_debug, "WINC1500_IP address bytes: %x\n",  current_sock_addr.sin_addr.s_addr);
//	winc_debug(_winc_debug, "WINC1500_Port: %d\n",  addr.get_port());

	_mutex.lock();

//	if (ws->ws_type == SOCK_STREAM) {
	rc = WINC_SOCKET(connect)(socket->id, (struct sockaddr *)&current_sock_addr, sizeof(current_sock_addr));

	winc_debug(_winc_debug, "rc = %i\n",  rc);
	winc_debug(_winc_debug, "Waiting for semaphore release...");

	socket_connected.wait();


//	} else {
//		/*
//		 * UDP socket. Docs talk about different kind fo bind? XXXX check
//		 */
//		rc = SOCK_ERR_INVALID;
//	}
//	ws->ws_poll = 1;

	_ids[socket->id]  = true;
	_socket_obj[socket->id] = (uint32_t)socket;
	socket->connected = true;


	_mutex.unlock();

//	return winc1500_err_to_mn_err(rc);

    return rc;
}

int WINC1500Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::socket_send(void *handle, const void *data, unsigned size)
{

	sint16	s16Ret;

	struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;

	winc_debug(_winc_debug, "socket_send entry point\n",  socket->id);
	winc_debug(_winc_debug, "Socket ID: %i\n",  socket->id);
	winc_debug(_winc_debug, "Data to send: %s\n",  data);
	winc_debug(_winc_debug, "Data size: %i\n",  size);
	winc_debug(_winc_debug, "strlen: %i\n",  strlen((char *)data));


	// send data
	s16Ret = WINC_SOCKET(send)(socket->id, (void *)data, size, 0);

	if(s16Ret != SOCK_ERR_NO_ERROR)
	{
		winc_debug(_winc_debug, "Error occured during socket_send, err_code = %i\n",  s16Ret);

		return NSAPI_ERROR_UNSUPPORTED;
	}
	else
	{
		socket_data_sent.wait();

		winc_debug(_winc_debug, "After send semaphore realease");
		winc_debug(_winc_debug, "Data send size: %i", read_data_size);

	    return read_data_size;
	}

}

int WINC1500Interface::socket_recv(void *handle, void *data, unsigned size)
{

	_mutex.lock();
	unsigned recv = 0;
	struct WINC1500_socket *socket = (struct WINC1500_socket *)handle;
	char *ptr = (char *)data;

	if (!socket->connected) {
		_mutex.unlock();
		return NSAPI_ERROR_CONNECTION_LOST;
	}

	sint16 err = WINC_SOCKET(recv)(socket->id, (void *) data, (uint16) size, 0);
	if (err != SOCK_ERR_NO_ERROR) {
		winc_debug(_winc_debug, "Error requesting receive. err_code = %i", err);
	}
	else {
		winc_debug(_winc_debug, "Successfully requested recv");

		socket_data_recv.wait();

		winc_debug(_winc_debug, "Recv semaphore released!");
		winc_debug(_winc_debug, "Recv data size: %i", sizeof(data));

	    return received_data_size;

	}

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

void WINC1500Interface::wifi_cb(uint8_t u8MsgType, void *pvMsg)
{
	switch (u8MsgType) {
	case M2M_WIFI_RESP_SCAN_DONE:
	{
		tstrM2mScanDone *pstrInfo = (tstrM2mScanDone *)pvMsg;
		scan_request_index = 0;



		if (pstrInfo->u8NumofCh >= 1) {
			m2m_wifi_req_scan_result(scan_request_index);
			scan_request_index++;
		} else {
//			m2m_wifi_request_scan(M2M_WIFI_CH_ALL);
		}


		break;
	}

	case M2M_WIFI_RESP_SCAN_RESULT:
	{
		tstrM2mWifiscanResult *pstrScanResult = (tstrM2mWifiscanResult *)pvMsg;
		uint16_t demo_ssid_len;
		uint16_t scan_ssid_len = strlen((const char *)pstrScanResult->au8SSID);

		memcpy(&found_ap_list[scan_request_index], &pstrScanResult, sizeof(pstrScanResult));

		/* display founded AP. */
		printf("[%d] SSID:%s\r\n", scan_request_index, pstrScanResult->au8SSID);

		//cast the ASF AP struct to mbed api AP struct
//		nsapi_wifi_ap_t ap = {0};
		strncpy(found_ap_list[scan_request_index].ssid, (const char *) pstrScanResult->au8SSID, 33);
//		found_ap_list[scan_request_index].ssid = (char *) pstrScanResult->au8SSID;
		found_ap_list[scan_request_index].rssi = pstrScanResult->s8rssi;
		found_ap_list[scan_request_index].security = (nsapi_security_t) pstrScanResult->u8AuthType;
		found_ap_list[scan_request_index].channel = pstrScanResult->u8ch;
		for (int i=0; i<6; i++) {
			found_ap_list[scan_request_index].bssid[i] = pstrScanResult->au8BSSID[i];
		}

//		delete[] ap;
//		res[cnt] = WiFiAccessPoint(ap);

		num_founded_ap = m2m_wifi_get_num_ap_found();
//		if (scan_ssid_len) {
//			/* check same SSID. */
//			demo_ssid_len = strlen((const char *)MAIN_WLAN_SSID);
//			if
//			(
//				(demo_ssid_len == scan_ssid_len) &&
//				(!memcmp(pstrScanResult->au8SSID, (uint8_t *)MAIN_WLAN_SSID, demo_ssid_len))
//			) {
//				/* A scan result matches an entry in the preferred AP List.
//				 * Initiate a connection request.
//				 */
//				printf("Found %s \r\n", MAIN_WLAN_SSID);
//
//				m2m_wifi_connect((char *)MAIN_WLAN_SSID,
//						sizeof(MAIN_WLAN_SSID),
//						MAIN_WLAN_AUTH,got_scan_result
//						(void *)MAIN_WLAN_PSK,
//						M2M_WIFI_CH_ALL);
//				break;
//			}
//		}

		if (scan_request_index < num_founded_ap) {
			m2m_wifi_req_scan_result(scan_request_index);
			scan_request_index++;
		} else {
//			printf("can not find AP %s\r\n", MAIN_WLAN_SSID);
//			m2m_wifi_request_scan(M2M_WIFI_CH_ALL);
			getInstance().got_scan_result.release();

		}

		break;
	}

	case M2M_WIFI_RESP_CON_STATE_CHANGED:
	{
		tstrM2mWifiStateChanged *pstrWifiState = (tstrM2mWifiStateChanged *)pvMsg;
		if (pstrWifiState->u8CurrState == M2M_WIFI_CONNECTED) {

			m2m_wifi_request_dhcp_client();

		} else if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED) {
			printf("M2M_WIFI_RESP_CON_STATE_CHANGED. DISCONENCTED\r\n");

			printf("Wi-Fi disconnected\r\n");

			getInstance().disconnected.release();
//			/* Request scan. */
//			m2m_wifi_request_scan(M2M_WIFI_CH_ALL);
		}

		break;
	}

	case M2M_WIFI_REQ_CONN:
	{

		printf("M2M_WIFI_REQ_CONN");

		break;
	}

	case M2M_WIFI_REQ_DHCP_CONF:
	{
		uint8_t *pu8IPAddress = (uint8_t *)pvMsg;
		printf("Wi-Fi connected\r\n");
		printf("Wi-Fi IP is %u.%u.%u.%u\r\n",
				pu8IPAddress[0], pu8IPAddress[1], pu8IPAddress[2], pu8IPAddress[3]);

		memcpy(&(getInstance().IP_addr.ip_addr_8), &pu8IPAddress, sizeof(getInstance().IP_addr.ip_addr_8));

		winc_debug(getInstance()._winc_debug, "IP address: 0x%x%x%x%x", getInstance().IP_addr.ip_addr_8[0], getInstance().IP_addr.ip_addr_8[1], getInstance().IP_addr.ip_addr_8[2], getInstance().IP_addr.ip_addr_8[3]);

		//release the connection semaphore
		getInstance().connected.release();

		break;
	}

	default:
	{
		break;
	}
	}
}

void WINC1500Interface::socket_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg)
{

	winc_debug(getInstance()._winc_debug, "socket_cb entry point");

	tstrSocketConnectMsg *pstrConnect;
	tstrSocketRecvMsg *pstrRecvMsg;
	int send_ret;

	switch (u8Msg) {
	case SOCKET_MSG_CONNECT:

		pstrConnect = (tstrSocketConnectMsg *)pvMsg;

		if (pstrConnect->s8Error == 0)
		{
			//no error
			winc_debug(getInstance()._winc_debug, "Socket successfully connected!");

			getInstance().socket_connected.release();
		}
		else
		{
			winc_debug(getInstance()._winc_debug, "Socket connect failed!");
			winc_debug(getInstance()._winc_debug, "err_code = %i", (int) pstrConnect->s8Error);
		}

//		msg_connect = (tstrSocketConnectMsg*)msg_data;
//		data.sock_connected.result = msg_connect->s8Error;
//		if (msg_connect->s8Error < 0) {
//			/* Remove reference. */
//			HTTP_LOG(DEBUG, "Socket error: %i", msg_connect->s8Error);
//
//			_http_client_clear_conn(module, _hwerr_to_stderr(msg_connect->s8Error));
//
//		} else {
//			/* Send event to callback. */
//			if (module->cb != NULL) {
//				module->cb(module, HTTP_CLIENT_CALLBACK_SOCK_CONNECTED, &data);
//			}
//			module->req.state = STATE_REQ_SEND_HEADER;
//			/* Start timer. */
//			sw_timer_enable_callback(module->config.timer_inst, module->timer_id, module->config.timeout);
//			/* Start receive packet. */
//			_http_client_recv_packet(module);
//			/* Try to check the FSM. */
//			_http_client_request(module);
//		}
		break;

	case SOCKET_MSG_RECV:

		pstrRecvMsg = (tstrSocketRecvMsg*) pvMsg;

		if((pstrRecvMsg->pu8Buffer != NULL) && (pstrRecvMsg->s16BufferSize > 0))
		{
			winc_debug(getInstance()._winc_debug, "Received some data!");
			winc_debug(getInstance()._winc_debug, "Data size: %i", pstrRecvMsg->s16BufferSize);
//			winc_debug(getInstance()._winc_debug, "Data: %s", pstrRecvMsg->pu8Buffer);
			winc_debug(getInstance()._winc_debug, "remaining data size: %i", pstrRecvMsg->u16RemainingSize);

			memcpy(&(getInstance().received_data), pstrRecvMsg->pu8Buffer, sizeof(getInstance().received_data));
			getInstance().received_data_size = pstrRecvMsg->s16BufferSize;

			if(pstrRecvMsg->u16RemainingSize != 0) {
				winc_debug(getInstance()._winc_debug, "Some data left [%i], waiting...", pstrRecvMsg->u16RemainingSize);
			}
			else {
				winc_debug(getInstance()._winc_debug, "All data received!");
				getInstance().socket_data_recv.release();
			}



		}

//		/* Start post processing. */
//		if (msg_recv->s16BufferSize > 0) {
//			_http_client_recved_packet(module, msg_recv->s16BufferSize);
//		} else {
//			/* Socket was occurred errors. Close this session. */
//			HTTP_LOG(DEBUG, "Socket error: %i", msg_recv->s16BufferSize);
//
//			_http_client_clear_conn(module, _hwerr_to_stderr(msg_recv->s16BufferSize));
//		}
//		/* COntinue to receive the packet. */
//		_http_client_recv_packet(module);
		break;
	case SOCKET_MSG_SEND:

		winc_debug(getInstance()._winc_debug, "Some data was sent!");

		send_ret = *(int16_t*)pvMsg;
		winc_debug(getInstance()._winc_debug, "pvMSG: %i", send_ret);

		if (send_ret < 0) {
			/* Send failed. */
			winc_debug(getInstance()._winc_debug, "Socket error: %i", send_ret);

		} else {
			/* Try to check the FSM. */

			getInstance().read_data_size = send_ret;
			getInstance().socket_data_sent.release();

		}

//		send_ret = *(int16_t*)msg_data;
//		if (send_ret < 0) {
//			/* Send failed. */
//			HTTP_LOG(DEBUG, "Socket error: %i", send_ret);
//
//			_http_client_clear_conn(module, _hwerr_to_stderr(send_ret));
//
//		} else {
//			/* Try to check the FSM. */
//			_http_client_request(module);
//		}
//		/* Disable sending flag. */
//		module->sending = 0;
		break;
	default:
		break;
	}

}



void WINC1500Interface::wifi_thread_cb()
{
	while (1) {
		/* Handle pending events from network controller. */
		while (m2m_wifi_handle_events(NULL) != M2M_SUCCESS) {
		}
	}
}

void WINC1500Interface::dnsResolveCallback(uint8* pu8HostName ,uint32 u32ServerIP)
{

	winc_debug(getInstance()._winc_debug, "resolve_cb for IP address %s", pu8HostName);
	if(u32ServerIP != 0)
	{

		winc_debug(getInstance()._winc_debug, "resolve_cb: %s IP address is %d.%d.%d.%d\r\n\r\n", pu8HostName,
					(int)IPV4_BYTE(u32ServerIP, 0), (int)IPV4_BYTE(u32ServerIP, 1),
					(int)IPV4_BYTE(u32ServerIP, 2), (int)IPV4_BYTE(u32ServerIP, 3));

		winc_debug(getInstance()._winc_debug, "DNS resolved. serve IP: 0x%x", u32ServerIP);
		getInstance().current_sock_addr.sin_addr.s_addr = u32ServerIP;
		getInstance().socket_dns_resolved.release();
	}
	else
	{
		winc_debug(getInstance()._winc_debug, "Got NULL resolve address!");
	}
}







