#include "WINC1500Interface.h"

#include "TCPSocket.h"

#include "wifi-winc1500/mbed_bsp/bsp_mbed.h"



extern "C"
{

	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_wifi.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/source/m2m_hif.h"
	#include "wifi-winc1500/winc1500/host_drv/driver/include/m2m_types.h"

}

uint8_t WINC1500Interface::scan_request_index;
	/** Number of APs found. */
uint8_t WINC1500Interface::num_founded_ap;

nsapi_wifi_ap_t WINC1500Interface::found_ap_list[MAX_NUM_APs];


WINC1500Interface::WINC1500Interface() {

	//init sequence
	tstrWifiInitParam param;
	int8_t ret;


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
    return NSAPI_ERROR_UNSUPPORTED;
}

int WINC1500Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
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

void WINC1500Interface::wifi_thread_cb()
{
	while (1) {
		/* Handle pending events from network controller. */
		while (m2m_wifi_handle_events(NULL) != M2M_SUCCESS) {
		}
	}
}





