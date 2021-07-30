#include "pch.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include "log.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */

int route_print()
{

    // Declare and initialize variables.

    /* variables used for GetIfForwardTable */
    PMIB_IPFORWARDTABLE pIpForwardTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    char szDestIp[128];
    char szMaskIp[128];
    char szGatewayIp[128];

    struct in_addr IpAddr;

    int i;

    pIpForwardTable =
        (MIB_IPFORWARDTABLE*)MALLOC(sizeof(MIB_IPFORWARDTABLE));
    if (pIpForwardTable == NULL) {
        ERROR2("Error allocating memory");
        return 1;
    }

    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) ==
        ERROR_INSUFFICIENT_BUFFER) {
        FREE(pIpForwardTable);
        pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(dwSize);
        if (pIpForwardTable == NULL) {
            ERROR2("Error allocating memory");
            return 1;
        }
    }

    /* Note that the IPv4 addresses returned in
     * GetIpForwardTable entries are in network byte order
     */
    if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR) {
        INFO("\tNumber of entries: %d",
            (int)pIpForwardTable->dwNumEntries);
        for (i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {
            /* Convert IPv4 addresses to strings */
            IpAddr.S_un.S_addr =
                (u_long)pIpForwardTable->table[i].dwForwardDest;
            strcpy_s(szDestIp, sizeof(szDestIp), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr =
                (u_long)pIpForwardTable->table[i].dwForwardMask;
            strcpy_s(szMaskIp, sizeof(szMaskIp), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr =
                (u_long)pIpForwardTable->table[i].dwForwardNextHop;
            strcpy_s(szGatewayIp, sizeof(szGatewayIp), inet_ntoa(IpAddr));

            INFO("\n\tRoute[%d] Dest IP: %s", i, szDestIp);
            INFO("\tRoute[%d] Subnet Mask: %s", i, szMaskIp);
            INFO("\tRoute[%d] Next Hop: %s", i, szGatewayIp);
            INFO("\tRoute[%d] If Index: %ld", i,
                pIpForwardTable->table[i].dwForwardIfIndex);
            INFO("\tRoute[%d] Type: %ld - ", i,
                pIpForwardTable->table[i].dwForwardType);
            switch (pIpForwardTable->table[i].dwForwardType) {
            case MIB_IPROUTE_TYPE_OTHER:
                INFO("other");
                break;
            case MIB_IPROUTE_TYPE_INVALID:
                INFO("invalid route");
                break;
            case MIB_IPROUTE_TYPE_DIRECT:
                INFO("local route where next hop is final destination");
                break;
            case MIB_IPROUTE_TYPE_INDIRECT:
                INFO("remote route where next hop is not final destination");
                break;
            default:
                INFO("UNKNOWN Type value");
                break;
            }
            INFO("\tRoute[%d] Proto: %ld - ", i,
                pIpForwardTable->table[i].dwForwardProto);
            switch (pIpForwardTable->table[i].dwForwardProto) {
            case MIB_IPPROTO_OTHER:
                INFO("other");
                break;
            case MIB_IPPROTO_LOCAL:
                INFO("local interface");
                break;
            case MIB_IPPROTO_NETMGMT:
                INFO("static route set through network management");
                break;
            case MIB_IPPROTO_ICMP:
                INFO("result of ICMP redirect");
                break;
            case MIB_IPPROTO_EGP:
                INFO("Exterior Gateway Protocol (EGP)");
                break;
            case MIB_IPPROTO_GGP:
                INFO("Gateway-to-Gateway Protocol (GGP)");
                break;
            case MIB_IPPROTO_HELLO:
                INFO("Hello protocol");
                break;
            case MIB_IPPROTO_RIP:
                INFO("Routing Information Protocol (RIP)");
                break;
            case MIB_IPPROTO_IS_IS:
                INFO
                ("Intermediate System-to-Intermediate System (IS-IS) protocol");
                break;
            case MIB_IPPROTO_ES_IS:
                INFO("End System-to-Intermediate System (ES-IS) protocol");
                break;
            case MIB_IPPROTO_CISCO:
                INFO("Cisco Interior Gateway Routing Protocol (IGRP)");
                break;
            case MIB_IPPROTO_BBN:
                INFO("BBN Internet Gateway Protocol (IGP) using SPF");
                break;
            case MIB_IPPROTO_OSPF:
                INFO("Open Shortest Path First (OSPF) protocol");
                break;
            case MIB_IPPROTO_BGP:
                INFO("Border Gateway Protocol (BGP)");
                break;
            case MIB_IPPROTO_NT_AUTOSTATIC:
                INFO("special Windows auto static route");
                break;
            case MIB_IPPROTO_NT_STATIC:
                INFO("special Windows static route");
                break;
            case MIB_IPPROTO_NT_STATIC_NON_DOD:
                INFO("special Windows static route not based on Internet standards");
                break;
            default:
                INFO("UNKNOWN Proto value");
                break;
            }

            INFO("\tRoute[%d] Age: %ld", i,
                pIpForwardTable->table[i].dwForwardAge);
            INFO("\tRoute[%d] Metric1: %ld", i,
                pIpForwardTable->table[i].dwForwardMetric1);
        }
        FREE(pIpForwardTable);
    }
    else {
        ERROR2("\tGetIpForwardTable failed.");
        FREE(pIpForwardTable);
        return 1;
    }
    return 0;
}