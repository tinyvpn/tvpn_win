#include "pch.h"
#include <iostream>
#include <string>
#include <fcntl.h>
#include <io.h>

#include "tuntap_windows_service.hpp"
#include "base.h"
#include "ssl_client2.h"
#include "http_client.h"
#include "sockutl.h"
#include "stringutl.h"
#include "sockhttp.h"
#include "timeutl.h"
#include "obfuscation_utl.h"
#include "win_common.h"
#include "tun_socket.h"

using namespace tuntap_service;
DWORD WINAPI WorkThread(LPVOID lpParameter);
time_t sendTime;
std::string g_default_gateway;

int exec_cmd(std::string& cmd)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		(TCHAR*)cmd.c_str(),        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		ERROR2("CreateProcess failed (%d).", GetLastError());
		return 1;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	INFO("exec cmd:%s", cmd.c_str());
	return 0;
}
int platform_init()
{
	/* Disable the "application crashed" popup. */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
		SEM_NOOPENFILEERRORBOX);

#if !defined(__MINGW32__)
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	_setmode(0, _O_BINARY);
	_setmode(1, _O_BINARY);
	_setmode(2, _O_BINARY);

	/* Disable stdio output buffering. */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	return 0;
}

const int BUF_SIZE = 4096 * 4;
const int MSGSIZE = 4096 * 4;
int g_protocol = kSslType;
uint32_t g_private_ip;
std::string global_private_ip;
std::string global_default_gateway_ip;
uint64_t g_fd_tun_dev;
std::string target_test_ip; //="159.65.226.184";
uint16_t target_test_port;
std::string web_server_ip = "www.tinyvpn.xyz";
static uint32_t in_traffic, out_traffic;
static int g_isRun;
//static int client_sock;
static int g_in_recv_tun;
static int g_in_recv_socket;
static SOCKET g_client_sock;

static int firstOpen = 0;
//int current_traffic = 0 ;  //bytes
uint32_t g_day_traffic;
uint32_t g_month_traffic;

DWORD g_BytesTransferred = 0;
VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped)
{
//	_tprintf(TEXT("Error code:\t%x\n"), dwErrorCode);
//	_tprintf(TEXT("Number of bytes:\t%x\n"), dwNumberOfBytesTransfered);
	g_BytesTransferred = dwNumberOfBytesTransfered;
}
static char g_tcp_buf[BUF_SIZE * 2];
static int g_tcp_len;
OVERLAPPED w_ol = { 0 };

int write_tun(char* ip_packet_data, int ip_packet_len) {
	int len;
	if (g_tcp_len != 0) {
		if (ip_packet_len + g_tcp_len > sizeof(g_tcp_buf)) {
			ERROR2("relay size over %lu", sizeof(g_tcp_buf));
			g_tcp_len = 0;
			return 1;
		}
		memcpy(g_tcp_buf + g_tcp_len, ip_packet_data, ip_packet_len);
		ip_packet_data = g_tcp_buf;
		ip_packet_len += g_tcp_len;
		g_tcp_len = 0;
		DEBUG2("relayed packet:%d", ip_packet_len);
	}

	while (1) {
		if (ip_packet_len == 0)
			break;
		// todo: recv from socket, send to utun1
		if (ip_packet_len < 20) {
			ERROR2("less than ip header:%d.", ip_packet_len);
			memcpy(g_tcp_buf, ip_packet_data, ip_packet_len);
			g_tcp_len = ip_packet_len;
			break;
		}
		char* iph = (char *)ip_packet_data;
		len = *(uint16_t*)(iph + 2);
		len = ntohs(len);

		if (ip_packet_len < len) {
			if (len > BUF_SIZE) {
				ERROR2("something error1.%x,%x,data:%s", len, ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data, ip_packet_len)).c_str());
				g_tcp_len = 0;
			}
			else {
				DEBUG2("relay to next packet:%d,current buff len:%d", ip_packet_len, g_tcp_len);
				if (g_tcp_len == 0) {
					memcpy(g_tcp_buf + g_tcp_len, ip_packet_data, ip_packet_len);
					g_tcp_len += ip_packet_len;
				}
			}
			break;
		}

		if (len > BUF_SIZE) {
			ERROR2("something error.%x,%x", len, ip_packet_len);
			g_tcp_len = 0;
			break;
		}
		else if (len == 0) {
			ERROR2("len is zero.%x,%x", len, ip_packet_len); //string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
			g_tcp_len = 0;
			break;
		}

		uint32_t ip_src = *(uint32_t*)(iph + 12);
		uint32_t ip_dst = *(uint32_t*)(iph + 16);

		DEBUG2("send to utun, from(%x) to (%x) with size:%d,%s", ip_src, ip_dst, len, string_utl::HexEncode(std::string(ip_packet_data, len)).c_str());
		BOOL bErrorFlag = FALSE;
		DWORD dwBytesWritten = 0;
		ResetEvent(w_ol.hEvent);
		bErrorFlag = WriteFile(
			(HANDLE)g_fd_tun_dev,           // open file handle
			ip_packet_data,      // start of data to write
			len,  // number of bytes to write
			&dwBytesWritten, // number of bytes that were written
			&w_ol);            // no overlapped structure
		if (FALSE == bErrorFlag)
		{
			int ret = (int)GetLastError();
			if (ret != ERROR_IO_PENDING) {
				ERROR2( "Terminal failure: Unable to write file. GetLastError=" , ret);
				CloseHandle((HANDLE)g_fd_tun_dev);
				return 1;
			}
			//DWORD read = 0;
			ret = GetOverlappedResult((HANDLE)g_fd_tun_dev, &w_ol, &dwBytesWritten, TRUE);
			if (!ret) {
				ERROR2("GetOverlappedResult error: ", (int)GetLastError());
				CloseHandle((HANDLE)g_fd_tun_dev);
				return 1;
			}
		}
		DEBUG2("write data:%d", dwBytesWritten);
		SetEvent(w_ol.hEvent);

		ip_packet_len -= len;
		ip_packet_data += len;
	}
	return 0;
}
int write_tun_http(char* ip_packet_data, int ip_packet_len) {
	static uint32_t g_iv = 0x87654321;
	int len;
	if (g_tcp_len != 0) {
		if (ip_packet_len + g_tcp_len > sizeof(g_tcp_buf)) {
			INFO("relay size over %d", sizeof(g_tcp_buf));
			g_tcp_len = 0;
			return 1;
		}
		memcpy(g_tcp_buf + g_tcp_len, ip_packet_data, ip_packet_len);
		ip_packet_data = g_tcp_buf;
		ip_packet_len += g_tcp_len;
		g_tcp_len = 0;
		INFO("relayed packet:%d", ip_packet_len);
	}
	std::string http_packet;
	int http_head_length, http_body_length;
	while (1) {
		if (ip_packet_len == 0)
			break;
		http_packet.assign(ip_packet_data, ip_packet_len);
		if (sock_http::pop_front_xdpi_head(http_packet, http_head_length, http_body_length) != 0) {  // decode http header fail
			DEBUG2("relay to next packet:%d,current buff len:%d", ip_packet_len, g_tcp_len);
			if (g_tcp_len == 0) {
				memcpy(g_tcp_buf + g_tcp_len, ip_packet_data, ip_packet_len);
				g_tcp_len += ip_packet_len;
			}
			break;
		}
		ip_packet_len -= http_head_length;
		ip_packet_data += http_head_length;
		obfuscation_utl::decode((unsigned char*)ip_packet_data, 4, g_iv);
		obfuscation_utl::decode((unsigned char*)ip_packet_data + 4, http_body_length - 4, g_iv);

		char* iph = (char*)ip_packet_data;
		len = *(uint16_t*)(iph + 2);
		len = ntohs(len);
		uint32_t ip_src = *(uint32_t*)(iph + 12);
		uint32_t ip_dst = *(uint32_t*)(iph + 16);

		printf("send to tun,http, from(%x) to (%x) with size:%d, header:%d,body:%d", ip_src,
			ip_dst, len, http_head_length, http_body_length);
		//sys_utl::tun_dev_write(g_fd_tun_dev, (void*)ip_packet_data, len);
		BOOL bErrorFlag = FALSE;
		DWORD dwBytesWritten = 0;
		ResetEvent(w_ol.hEvent);
		bErrorFlag = WriteFile(
			(HANDLE)g_fd_tun_dev,           // open file handle
			ip_packet_data,      // start of data to write
			len,  // number of bytes to write
			&dwBytesWritten, // number of bytes that were written
			&w_ol);            // no overlapped structure
		if (FALSE == bErrorFlag)
		{
			int ret = (int)GetLastError();
			if (ret != ERROR_IO_PENDING) {
				ERROR2("Terminal failure: Unable to write file. GetLastError=%d", ret);
				CloseHandle((HANDLE)g_fd_tun_dev);
				return 1;
			}
			//DWORD read = 0;
			ret = GetOverlappedResult((HANDLE)g_fd_tun_dev, &w_ol, &dwBytesWritten, TRUE);
			if (!ret) {
				ERROR2("GetOverlappedResult error: %d" ,(int)GetLastError());
				CloseHandle((HANDLE)g_fd_tun_dev);
				return 1;
			}
		}
		SetEvent(w_ol.hEvent);

		ip_packet_len -= http_body_length;
		ip_packet_data += http_body_length;
	}
	return 0;
}
DWORD WINAPI WorkThread(LPVOID lpParameter)
{
	INFO("start tun recv thread.");
	OVERLAPPED ol = { 0 };
	ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!ol.hEvent)
	{
		_tprintf_s(TEXT("Error creating I/O event for reading second line\n"));
		return 1;
	}

	while (g_isRun != 0) {
		static VpnPacket vpn_packet(4096);
		int readed_from_tun;
		vpn_packet.reset();
		//readed_from_tun = sys_utl::tun_dev_read(g_fd_tun_dev, vpn_packet.data(), vpn_packet.remain_size());
		DWORD  dwBytesRead = 0;
		//if (FALSE == ReadFileEx((HANDLE)g_fd_tun_dev, vpn_packet.data(), vpn_packet.remain_size(), &ol, FileIOCompletionRoutine))
		ResetEvent(ol.hEvent);
		if (FALSE == ReadFile((HANDLE)g_fd_tun_dev, vpn_packet.data(), vpn_packet.remain_size(), &dwBytesRead, &ol))
		{
			int ret = (int)GetLastError();
			if (ret != ERROR_IO_PENDING) {
				ERROR2("Terminal failure: Unable to read from file. GetLastError=%d", ret);
				CloseHandle((HANDLE)g_fd_tun_dev);
				break;
			}
			//DWORD read = 0;
			ret = GetOverlappedResult((HANDLE)g_fd_tun_dev, &ol, &dwBytesRead, TRUE);
			if (!ret) {
				ERROR2("GetOverlappedResult error: %d", (int)GetLastError());
				CloseHandle((HANDLE)g_fd_tun_dev);
				break;
			}
		}
//		else {
		SetEvent(ol.hEvent);
		//}

		//readed_from_tun = g_BytesTransferred;
		readed_from_tun = dwBytesRead;
		DEBUG2("recv from tun:%d", readed_from_tun);

		vpn_packet.set_back_offset(vpn_packet.front_offset() + readed_from_tun);
		if (readed_from_tun < 20) {
			ERROR2("tun_dev_read error, size:%d", readed_from_tun);
			break;
		}
		if (readed_from_tun > 0)
		{
			//struct ip* iph = (struct ip*)vpn_packet.data();
			char* iph = (char*)vpn_packet.data();

			uint32_t ip_src = *(uint32_t*)(iph + 12);
			uint32_t ip_dst = *(uint32_t*)(iph + 16);
			if (g_private_ip != ip_src) {
				ERROR2("src_ip mismatch:%x,%x,%s", g_private_ip, ip_src, string_utl::HexEncode(std::string(iph, readed_from_tun)).c_str());
				continue;
			}
			DEBUG2("recv from tun, from(%x) to (%x) with size:%d,%s", ip_src, ip_dst, readed_from_tun, string_utl::HexEncode(std::string(iph, readed_from_tun)).c_str());
			//file_utl::write(sockid, vpn_packet.data(), readed_from_tun);
			out_traffic += readed_from_tun;
			if (g_protocol == kSslType) {
				if (ssl_write(vpn_packet.data(), readed_from_tun) != 0) {
					ERROR2("ssl_write error");
					break;
				}
			}
			else if (g_protocol == kHttpType) {
				http_write(vpn_packet);
			}
			sendTime = time_utl::localtime();
		}
	}
	CloseHandle(ol.hEvent);
	return 0;
}
int tun_socket_init()
{
	platform_init();
	//init_logging(false);
	string_utl::set_random_http_domains();
	sock_http::init_http_head();

	//boost::asio::io_context io;
	OpenFile("vlog.txt");
	SetLogLevel(1);

	//加载套接字库  
	WORD wVersionRequested;
	WSAData wsaData;
	int err;
	INFO("This is a Client side application: ver 1.2");
	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		//Tell the user that we could not find a usable WinSock Dll.  
		ERROR2("WSAStartup() called failed!\n");
		return -1;
	}
	else {
		printf("WSAStartup called successful!\n");
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		//Tell the user that we could not find a usable WinSock Dll.  
		ERROR2("winsock version ERROR2");
		WSACleanup();
		return -1;
	}

	MIB_IPFORWARDROW ipfrow;
	if (GetBestRoute(0x08080808, 0, &ipfrow) != NO_ERROR) {
		ERROR2("GetBestRoute error.");
		return -1;
	}
	g_default_gateway = socket_utl::socketaddr_to_string(ipfrow.dwForwardNextHop);
	INFO("GetBestRoute: %x,%x,%x,%s", ipfrow.dwForwardDest, ipfrow.dwForwardNextHop, ipfrow.dwForwardMask, g_default_gateway.c_str());

	return 0;
}
int login(std::string user_name, std::string password, std::string device_id,
	uint32_t& day_traffic, uint32_t& month_traffic, uint32_t& day_limit, uint32_t& month_limit, int& ret1, int& ret2)
{
	struct hostent* h;
	if ((h = gethostbyname(web_server_ip.c_str())) == NULL) {
		return 1;
	}
	std::string web_ip = inet_ntoa(*((struct in_addr*)h->h_addr));
	INFO("web ip:%s", web_ip.c_str());
	struct sockaddr_in serv_addr;
	SOCKET sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		INFO("socket() error");
		return 1;
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(web_ip.c_str());
	serv_addr.sin_port = htons(60315);

	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		INFO("connect() error!");
		return 1;
	}
	INFO("login, connect web server ok.");
	std::string strtemp;
	strtemp += (char)1;
	strtemp += device_id;
	strtemp += (char)'\n';
	strtemp += user_name;
	strtemp += (char)'\n';
	strtemp += password;
	INFO("send:%s", string_utl::HexEncode(strtemp).c_str());
	int ret = send(sock, (char*)strtemp.c_str(), (int)strtemp.size(), 0);
	char ip_packet_data[BUF_SIZE];
	ret = recv(sock, ip_packet_data, BUF_SIZE, 0);
	if (ret < 2 + 4 * sizeof(uint32_t))
		return 1;
	ip_packet_data[ret] = 0;
	INFO("recv from web_server:%s", string_utl::HexEncode(std::string(ip_packet_data, ret)).c_str());
	int pos = 0;
	ret1 = ip_packet_data[pos++];
	ret2 = ip_packet_data[pos++];
	day_traffic = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	month_traffic = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	day_limit = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	month_limit = ntohl(*(uint32_t*)(ip_packet_data + pos));

	closesocket(sock);
	INFO("recv login:%d,%d,%x,%x,%x,%x", ret1, ret2, day_traffic, month_traffic, day_limit, month_limit);
	//g_user_name = user_name;
	//g_password = password;

	//trafficCallback(day_traffic, month_traffic, day_limit, month_limit, ret1, ret2);
	return 0;
}

int connect_server(std::string& user_name, std::string& password, std::string& device_id, int premium)
{
	//The WinSock Dll is acceptable. Proceed  
	SOCKET sock;// = sockClient;
	//target_test_ip = "192.168.50.218";
	uint16_t port = 14433;
	int ret;
	if (g_protocol == kSslType) {
		if (init_ssl_client() != 0) {
			ERROR2("init ssl fail.");
			return 1;
		}
		INFO("connect ssl");
		ret = connect_ssl(target_test_ip, port, sock);
		if (ret != 0) {
			return 1;
		}
		if (sock == 0) {
			ERROR2("sock is zero.");
			return 1;
		}
	}
	else if (g_protocol == kHttpType) {
		if (connect_tcp(target_test_ip, port, sock) != 0)
			return 1;
	}
	else {
		ERROR2("protocol errror.");
		return 1;
	}
	g_client_sock = sock;

	INFO("connect ok.");
	std::string strPrivateIp;
	if (g_protocol == kSslType) {
		//device_id = "Win.000001";
		//g_user_name = "dudu@163.com";
		//g_password = "123456";
		get_private_ip(premium, device_id, user_name, password, strPrivateIp);
	}

	g_private_ip = *(uint32_t*)strPrivateIp.c_str();

	global_private_ip = socket_utl::socketaddr_to_string(g_private_ip);
	INFO("private_ip:%s", global_private_ip.c_str());
	return 0;
}
int stop_vpn(long value)
{
	g_isRun = 0;
	return 0;
}
int get_vpnserver_ip(std::string& user_name, std::string& password, std::string& device_id, int premium, std::string& country_code, 
	uint32_t& day_traffic, uint32_t& month_traffic, uint32_t& day_limit, uint32_t& month_limit) {
	struct hostent* h;
	if ((h = gethostbyname(web_server_ip.c_str())) == NULL) {
		return 1;
	}
	std::string web_ip = inet_ntoa(*((struct in_addr*)h->h_addr));
	INFO("web ip:%s", web_ip.c_str());
	struct sockaddr_in serv_addr;
	SOCKET sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		INFO("socket() error");
		return 1;
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(web_ip.c_str());
	serv_addr.sin_port = htons(60315);

	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		INFO("connect() error!");
		return 1;
	}
	INFO("connect web server ok.");

	std::string strtemp;
	strtemp += (char)0;
	strtemp += (char)premium;
	strtemp += country_code;
	if (premium <= 1)
		strtemp += device_id;
	else
		strtemp += user_name;
	INFO("send: %s", string_utl::HexEncode(strtemp).c_str());
	int ret = send(sock, (char*)strtemp.c_str(), (int)strtemp.size(), 0);
	char ip_packet_data[BUF_SIZE];
	ret = recv(sock, ip_packet_data, BUF_SIZE, 0);

	ip_packet_data[ret] = 0;
	INFO("recv from web_server:%s", string_utl::HexEncode(std::string(ip_packet_data, ret)).c_str());
	//current_traffic = 0;
	int pos = 0;
	day_traffic = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	month_traffic = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	day_limit = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	month_limit = ntohl(*(uint32_t*)(ip_packet_data + pos));
	pos += sizeof(uint32_t);
	g_day_traffic = day_traffic;
	g_month_traffic = month_traffic;
	if (premium <= 1) {
		if (day_traffic > day_limit) {
			//trafficCallback(day_traffic, month_traffic, day_limit, month_limit, target);
			return 2;
		}
	}
	else {
		if (month_traffic > month_limit) {
			//trafficCallback(day_traffic, month_traffic, day_limit, month_limit, target);
			return 2;
		}
	}
	//trafficCallback(day_traffic, month_traffic, day_limit, month_limit, target);

	std::string recv_ip(ip_packet_data + 16, ret - 16);
	std::vector<std::string> recv_data;
	string_utl::split_string(recv_ip, ',', recv_data);
	if (recv_data.size() < 1) {
		ERROR2("recv server ip data error.");
		//tunnel.close();
		return 1;
	}
	INFO("recv:%s", recv_data[0].c_str());
	std::vector<std::string>  server_data;
	string_utl::split_string(recv_data[0], ':', server_data);

	if (server_data.size() < 3) {
		ERROR2("parse server ip data error.");
		//tunnel.close();
		return 1;
	}
	//Log.i(TAG, "data:" + server_data[0]+","+server_data[1]+","+server_data[2]);
	g_protocol = std::stoi(server_data[0]);
	target_test_ip = server_data[1];
	//g_ip = "192.168.50.218";
	target_test_port = std::stoi(server_data[2]);
	INFO("protocol:%d,%s,%d", g_protocol, target_test_ip.c_str(), target_test_port);
	return 0;
}
int start_vpn(CWnd* wnd, std::string& user_name, std::string& password, std::string& device_id, int premium, std::string& country_code,
	uint32_t& day_traffic, uint32_t& month_traffic, uint32_t& day_limit, uint32_t& month_limit)
{
	// get vpnserver ip
	int ret = get_vpnserver_ip(user_name, password, device_id, premium, country_code, day_traffic, month_traffic, day_limit, month_limit);
	if (ret == 1) {
		//stopCallback(1, target);
		return 1;
	}
	else if (ret == 2) {
		//stopCallback(1, target);
		return 2;
	}
	if (connect_server(user_name, password, device_id, premium) != 0) {
		ERROR2("connect server error");
		return 0;
	}

	// open tun
	dev_config cfg;// = { "126.24.0.1", "255.255.0.0", "99.99.99.99" };
	cfg.local_ = global_private_ip;
	cfg.mask_ = "255.255.0.0";
	cfg.gateway_ = "99.99.99.99";

	cfg.dev_name_ = "VPN01";

	tuntap_windows_service tap;
	auto dev_list = tap.take_device_list();
	std::string guid;
	int find_dev=0;
	for (auto& i : dev_list)
	{
		INFO("dev name:%s, type:%d", i.name_.c_str(), i.dev_type_);
		//if (i.name_ == cfg.dev_name_)
		{
			cfg.guid_ = i.guid_;
			find_dev = 1;
			INFO("find tap ok.");
			break;
		}
	}
	static uint32_t error_id;
	if (find_dev == 0) {
		ERROR2("not find vpn dev.");
		closesocket(g_client_sock);

		error_id = 1;
		wnd->SendMessage(WM_ERROR_MESSAGE, (WPARAM)&error_id);
		return 1;
	}

	cfg.dev_type_ = tuntap_service::dev_tun;
	if (!tap.open(cfg))
	{
		ERROR2("open tun device fail!");
		return -1;
	}

	tap.get_handle(g_fd_tun_dev);

	route_print();
	std::string cmd;
	cmd = "route.exe delete " + target_test_ip;
	exec_cmd(cmd);
	cmd = "route.exe add "+target_test_ip+" mask 255.255.255.255 " + g_default_gateway;  //192.168.70.254
	exec_cmd(cmd);
	cmd = "route.exe add 0.0.0.0 mask 128.0.0.0 126.24.255.254";
	exec_cmd(cmd);
	cmd = "route.exe add 128.0.0.0 mask 128.0.0.0 126.24.255.254";
	exec_cmd(cmd);
//	cmd = "route.exe add "+ global_private_ip + " mask 255.255.255.255 126.24.255.254";
	cmd = "route.exe add 126.24.0.0 mask 255.255.0.0 126.24.255.254";
	exec_cmd(cmd);

	wnd->SendMessage(WM_CONNECTED_MESSAGE);

	INFO("fd:%d,%d", g_client_sock, g_fd_tun_dev);
	FD_SET fdRead;
	int nRet = 0;//记录发送或者接受的字节数
	TIMEVAL tv;//设置超时等待时间
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	int ip_packet_len;
	char ip_packet_data[BUF_SIZE];

	g_isRun = 1;
	DWORD dwThreadIDRecv = 0;
	HANDLE hand = CreateThread(NULL, 0, WorkThread, NULL, 0, &dwThreadIDRecv);//用来处理手法消息的进程
	if (hand == NULL)
	{
		ERROR2("Create work thread failed");
		//getchar();
		return 1;
	}
	in_traffic = 0;
	out_traffic = 0;
	w_ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	time_t lastTime = time_utl::localtime();
	time_t currentTime;
	time_t recvTime = time_utl::localtime();
	
	while (g_isRun != 0)
	{
		FD_ZERO(&fdRead);
		FD_SET(g_client_sock, &fdRead);
//		FD_SET(g_fd_tun_dev, &fdRead);
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		//只处理read事件，不过后面还是会有读写消息发送的
		//int maxfd = std::max(client_sock, g_fd_tun_dev);
		int nReady = select(0, &fdRead, NULL, NULL, &tv);

		if (nReady < 0) {
			ERROR2("select error:%d",nReady);
			break;
		}
		else if (nReady == 0) {
			DEBUG2("select timeout");
			continue;
		}

		if (FD_ISSET(g_client_sock, &fdRead))
		{
			ip_packet_len = 0;
			if (g_protocol == kSslType) {
				ret = ssl_read(ip_packet_data, ip_packet_len);
				if (ret != 0) {
					ERROR2("ssl_read error");
					break;
				}
			}
			else if (g_protocol == kHttpType) {
				ip_packet_len = recv(g_client_sock, ip_packet_data, BUF_SIZE, 0);
			}
			else {
				ERROR2("protocol error.");
				break;
			}
			if (ip_packet_len == 0)
				continue;
			in_traffic += ip_packet_len;
			DEBUG2("recv from socket, size:%d,%s", ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data, ip_packet_len)).c_str());
			if (g_protocol == kSslType) {
				if (write_tun((char*)ip_packet_data, ip_packet_len) != 0) {
					ERROR2("write_tun error");
					break;
				}
			}
			else if (g_protocol == kHttpType) {
				if (write_tun_http((char*)ip_packet_data, ip_packet_len) != 0) {
					ERROR2("write_tun error");
					break;
				}
			}
			recvTime = time_utl::localtime();
		}
		currentTime = time_utl::localtime();
		if (currentTime - recvTime > 60 && currentTime - sendTime > 60) {
			ERROR2("send or recv timeout");
			break;
		}
		if (currentTime - lastTime >= 1) {
			static uint32_t d, m;
			d = g_day_traffic + (in_traffic + out_traffic) / 1024;
			m = g_month_traffic + (in_traffic + out_traffic) / 1024;
			DEBUG2("send message: %d,%d", d, m);
			wnd->SendMessage(WM_TRAFFIC_MESSAGE, (WPARAM)&d, (LPARAM)&m);
			lastTime = time_utl::localtime();
		}

	}

	INFO("client quit...");
	WaitForSingleObject(hand, INFINITE);
	INFO("tun quit...");
	CloseHandle(w_ol.hEvent);

	//关闭套接字  
	closesocket(g_client_sock);
	//终止套接字库的使用  
	//WSACleanup();
	CloseHandle((HANDLE)g_fd_tun_dev);

	g_isRun = 0;
	wnd->SendMessage(WM_DISCONNECTED_MESSAGE);

	return 0;
}
