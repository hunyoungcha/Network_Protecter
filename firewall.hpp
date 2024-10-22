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


constexpr const char* FILTER = "inbound";
constexpr const char* CHECK_IP_QUREY = "SELECT ip FROM FirewallRules WHERE ip = ? LIMIT 1";


class CFirewall {
public:
    CFirewall();
    ~CFirewall();
    void PacketHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    int RunFirewall();
    int GetDeviceName();
    int BlockIP();
    bool CheckIPinDB(const std::string& ip);

private:
    
    char* m_chDevice;  
    pcap_if_t* m_pifAllDevices;
    std::queue<std::string> m_qIpQueue; //실시간으로 들어오는 패킷의 IP_src를 저장하는 큐
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    bool m_bCapturing = true;
    sqlite3* m_db;
    int m_nRc; //database의 상태를 저장하는 변수
    std::mutex m_dbMutex;

};
