// 최소 기능은 libpcap으로 구현
// 기능 구현 끝나면 eBPF 사용해서 구현해보기

#include "firewall.hpp"

// 패킷 캡처 콜백 함수
void CFirewall::packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    CFirewall* instance = reinterpret_cast<CFirewall*>(args);
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    // IP 패킷 확인
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        std::string strSourceIP = inet_ntoa(ip_header->ip_src);
        
        {
            std::lock_guard<std::mutex> lock(instance->m_queueMutex);
            instance->m_qIpQueue.push(strSourceIP);
        }
        
        instance->m_queueCV.notify_one();
    }
}

int CFirewall::GetDeviceName() {
    char chErrbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *device;

    if (pcap_findalldevs(&m_pifAllDevices, chErrbuf) == -1) {
        std::cerr << "Error finding devices: " << chErrbuf << std::endl;
        return 1;
    }

    //찾은 디바이스 출력
    int nDeviceCnt=1;
    std::vector<char*> vecDeviceList; //인덱싱을 위한 디바이스 벡터

    std::cout << "Devices :" << std::endl;
    
    for (device = m_pifAllDevices; device != NULL; device= device -> next){
        vecDeviceList.push_back(device->name);

        std::cout <<"   "<< nDeviceCnt << "." << device->name ;   

        if (device->description) {
            std::cout << " : " << device->description << std::endl;
        } else {
            std::cout << " : (Nothing)" << std::endl;
        }

        nDeviceCnt++;
    }

    //찾은 디바이스 중 원하는 디바이스 선택
    
    //(현재는 에러 처리 없이 구현)
    int nDeviceNum;
    std::cin >> nDeviceNum;

    if (nDeviceNum > vecDeviceList.size() || nDeviceNum <= 0){
        std::cout << "Wrong Input!" << std::endl; //나중에 에러처리 함수 만들어서 다시 처리 하기
        return 1;
    }

    m_chDevice = vecDeviceList[nDeviceNum-1] ;
    // 나중에 input 형식을 아래와 같이 변경해서 에러 처리하기
    // std::string strDeviceNum ;
    // if (Ini.isValidNumber(strDeviceNum) == false){
    // }
    // std::cout << strDeviceNum << std::endl;

    return 0;
}

int CFirewall::RunFirewall() {
    char chErrbuf[PCAP_ERRBUF_SIZE];

    // SIGINT 신호를 처리할 때 인스턴스의 SignalHandler를 사용할 수 있도록 this 포인터를 전달
    std::signal(SIGINT, CFirewall::SignalHandler);

    pcap_t *handle = pcap_open_live(m_chDevice, BUFSIZ, 1, 1000, chErrbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << m_chDevice << ": " << chErrbuf << std::endl;
        return 1;
    }

    std::thread blockerThread(&CFirewall::BlockIP, this);
    pcap_loop(handle, 0, CFirewall::packetHandler, reinterpret_cast<u_char*>(this));

    blockerThread.join();
    pcap_close(handle);
    pcap_freealldevs(m_pifAllDevices);

    return 0;
}




int CFirewall::BlockIP() {
    while (m_bCapturing) {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_queueCV.wait(lock, [] { return !m_qIpQueue.empty() || !m_bCapturing; });
        
        while (!m_qIpQueue.empty()) {
            std::string ipToBlock = m_qIpQueue.front();
            m_qIpQueue.pop();
            lock.unlock();

            // IP 차단 명령 실행 (예시: iptables 사용)
            std::string command = "iptables -A INPUT -s " + ipToBlock + " -j DROP";
            system(command.c_str());
            std::cout << "Blocked IP: " << ipToBlock << std::endl;

            lock.lock();
        }
    }

    return 0;
}


void CFirewall::SignalHandler(int signum){
    m_bCapturing = false;
    m_queueCV.notify_all();

    system("iptables -F");
}