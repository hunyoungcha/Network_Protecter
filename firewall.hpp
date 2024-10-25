#pragma once
#include "ini.hpp"
#include "configDB.hpp"


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

constexpr const char* FILTER = "inbound";


class CFirewall {
public:
    CFirewall(CConfigDB& IConfigDB);
    ~CFirewall();
    void PacketHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    int RunFirewall();
    int GetDeviceName();
    int BlockIP();
    int CheckPayload();
    bool isMaliciousIP();
    
private:
    
    char* m_chDevice;  
    pcap_if_t* m_pifAllDevices;
    std::queue<std::string> m_qIpQueue; //실시간으로 들어오는 패킷의 IP_src를 저장하는 큐
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    bool m_bCapturing = true;
    CConfigDB& m_configDB;
    struct ip m_ipHeader;
};  
