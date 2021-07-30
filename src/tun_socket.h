#pragma once
#define WM_TRAFFIC_MESSAGE (WM_USER + 100)
#define WM_CONNECTED_MESSAGE (WM_USER + 101)
#define WM_DISCONNECTED_MESSAGE (WM_USER + 102)
#define WM_ERROR_MESSAGE (WM_USER + 103)

int tun_socket_init();
int login(std::string user_name, std::string password, std::string device_id, 
	uint32_t& day_traffic, uint32_t& month_traffic, uint32_t& day_limit, uint32_t& month_limit, int& ret1, int& ret2);
int stop_vpn(long value);
int start_vpn(CWnd* wnd, std::string& user_name, std::string& password, std::string& device_id, int premium, std::string& country_code,
	uint32_t& day_traffic, uint32_t& month_traffic, uint32_t& day_limit, uint32_t& month_limit);

