//eBPF 구현 해보기

#include "firewall.hpp"


CFirewall::CFirewall(CConfigDB& IConfigDB) : m_configDB(IConfigDB) {}

CFirewall::~CFirewall() {
    m_bCapturing = false;
    m_queueCV.notify_all();

    system("iptables -F");
}


// 패킷 캡처 콜백 함수
void CFirewall::PacketHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
    //이더넷 헤더 
    m_ethHeader = (struct ether_header *) packet;
    
    // IP 패킷 확인
    if (ntohs(m_ethHeader->ether_type) == ETHERTYPE_IP) {
        
        //IP 해더
        m_ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

        if (m_ipHeader->ip_p == IPPROTO_TCP){
            //TCP 헤더
            m_tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + m_ipHeader->ip_hl * 4);
            bool isMalPayload = CheckPayload(packet);
        }

        // std::string strSrcIP = inet_ntoa(m_ipHeader->ip_src);
        

        // if (m_configDB.CheckIPinDB(strSrcIP)){
        //     std::cout << "DB에 저장된 IP 들어옴" << std::endl;
        // }

        // {
        //     std::lock_guard<std::mutex> lock(m_queueMutex);
        //     m_qIpQueue.push(strSrcIP);
        // }
        
        // m_queueCV.notify_one();
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

    struct bpf_program stFilter;

    pcap_compile(handle, &stFilter, FILTER, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &stFilter);
    pcap_freecode(&stFilter);  // 필터 메모리 해제

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

            // std::string command = "iptables -A OUTPUT -d " + ipToBlock + " -j DROP";

            // system(command.c_str());
            std::cout << "Blocked IP: " << ipToBlock << std::endl;
            lock.lock();
        }
    }

    return 0;
}
 


bool CFirewall::CheckPayload(const u_char* packet){
    bool isMalPayload = false;

    const u_char *payload = packet + sizeof(struct ether_header) + m_ipHeader->ip_hl * 4 + m_tcpHeader->th_off * 4;
    int payload_length = ntohs(m_ipHeader->ip_len) - (m_ipHeader->ip_hl * 4 + m_tcpHeader->th_off * 4);

    if (payload_length > 0) {
        printf("Payload (%d bytes):\n", payload_length);
        for (int i = 0; i < payload_length; i++) {
            printf("%02x ", payload[i]);  // 16진수 출력
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } 
    else {
        printf("No Payload.\n");
    }

    return isMalPayload;
}





// void CFirewall::SignalHandler(int signum) {     ini 파일로 빼서 모든 기능에 대한 signal 관리하기 (관리 함수 필요(게터세터?) )
//     m_bCapturing = false;
//     m_queueCV.notify_all();

//     system("iptables -F");
// }
