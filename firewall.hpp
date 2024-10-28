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
#include <netinet/tcp.h>
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
    bool CheckPayload(const u_char* packet);
    
private:
    
    //패킷 핸들링
    char* m_chDevice;  
    pcap_if_t* m_pifAllDevices;
    std::queue<std::string> m_qIpQueue; //실시간으로 들어오는 패킷의 IP_src를 저장하는 큐
    std::mutex m_IPqueueMutex;
    std::condition_variable m_queueCV;
    bool m_bCapturing = true;
    std::mutex m_


    //패킷 struct
    struct ip *m_ipHeader;
    struct ether_header *m_ethHeader;
    struct tcphdr *m_tcpHeader;

    //DB
    CConfigDB& m_configDB;
};  
