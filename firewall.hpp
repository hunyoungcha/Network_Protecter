#pragma once
#include "ini.hpp"

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <Packet.h>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


class CFirewall {
    public:
        static void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        int RunFirewall();
        int GetDeviceName();
    private:
        std::string m_strDevice;  
};

