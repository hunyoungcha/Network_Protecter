//eBPF 구현 해보기

#include "firewall.hpp"


CFirewall::CFirewall() {

    char* errMsg =0;

    m_nRc = sqlite3_open("firewall.db", &m_db);
    if (m_nRc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(m_db) << std::endl;
    }
}

CFirewall::~CFirewall() {
    if (m_db) {
        sqlite3_close(m_db);
    }
}

void CFirewall::SelectData() {
    char* errMsg = 0;
    const char* cmd = "SELECT * from FirewallRules";

    m_nRc = sqlite3_exec(m_db, cmd, CIni::SqlCallback, 0, &errMsg);
    if (m_nRc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

// 패킷 캡처 콜백 함수
void CFirewall::PacketHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
    
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    // IP 패킷 확인
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        std::string strSourceIP = inet_ntoa(ip_header->ip_src);
        
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_qIpQueue.push(strSourceIP);
        }
        
        m_queueCV.notify_one();
    }
}

int CFirewall::GetDeviceName() {
    char chErrbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *device;

    if (pcap_findalldevs(&m_pifAllDevices, chErrbuf) == -1) {
        std::cerr << "Error finding devices: " << chErrbuf << std::endl;
        return 1;
    }

    // 찾은 디바이스 출력
    int nDeviceCnt = 1;
    std::vector<char*> vecDeviceList; // 인덱싱을 위한 디바이스 벡터

    std::cout << "Devices :" << std::endl;
    
    for (device = m_pifAllDevices; device != NULL; device = device->next) {
        vecDeviceList.push_back(device->name);

        std::cout << "   " << nDeviceCnt << "." << device->name;   

        if (device->description) {
            std::cout << " : " << device->description << std::endl;
        } else {
            std::cout << " : (Nothing)" << std::endl;
        }

        nDeviceCnt++;
    }

    // 디바이스 선택
    int nDeviceNum;
    std::cin >> nDeviceNum;

    if (nDeviceNum > vecDeviceList.size() || nDeviceNum <= 0) {
        std::cout << "Wrong Input!" << std::endl;
        return 1;
    }

    m_chDevice = vecDeviceList[nDeviceNum - 1];

    return 0;
}

int CFirewall::RunFirewall() {
    char chErrbuf[PCAP_ERRBUF_SIZE];

    // std::signal(SIGINT, SignalHandler);

    pcap_t *handle = pcap_open_live(m_chDevice, BUFSIZ, 1, 1000, chErrbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << m_chDevice << ": " << chErrbuf << std::endl;
        return 1;
    }

    std::thread blockerThread(&CFirewall::BlockIP, this);
    pcap_loop(handle, 0, 
        [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
            auto* firewall = reinterpret_cast<CFirewall*>(args);  
            firewall->PacketHandler(header, packet);  
        }, reinterpret_cast<u_char*>(this));  
    
    blockerThread.join();
    pcap_close(handle);
    pcap_freealldevs(m_pifAllDevices);

    return 0;
}

int CFirewall::BlockIP() {
    while (m_bCapturing) {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_queueCV.wait(lock, [this] { return !m_qIpQueue.empty() || !m_bCapturing; });
        
        while (!m_qIpQueue.empty()) {
            std::string ipToBlock = m_qIpQueue.front();
            m_qIpQueue.pop();
            lock.unlock();

            std::string command = "iptables -A INPUT -s " + ipToBlock + " -j DROP";
            system(command.c_str());
            std::cout << "Blocked IP: " << ipToBlock << std::endl;

            lock.lock();
        }
    }

    return 0;
}
 




// void CFirewall::SignalHandler(int signum) {     ini 파일로 빼서 모든 기능에 대한 signal 관리하기 (관리 함수 필요(게터세터?) )
//     m_bCapturing = false;
//     m_queueCV.notify_all();

//     system("iptables -F");
// }
