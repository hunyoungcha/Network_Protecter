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
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <csignal>



class CFirewall {
    public:
        static void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        int RunFirewall();
        int GetDeviceName();
        int BlockIP();
    private:
        static void SignalHandler(int signum);
        char* m_chDevice;  
        pcap_if_t* m_pifAllDevices;
        std::queue<std::string> m_qIpQueue;
        std::mutex m_queueMutex;
        std::condition_variable m_queueCV;
        bool m_bCapturing = true;
};

