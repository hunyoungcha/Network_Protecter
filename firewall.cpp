#include "firewall.hpp"

// 패킷 캡처 콜백 함수
void CFirewall::packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    // 이더넷 헤더에서 목적지와 출발지 MAC 주소 출력
    std::cout << "Ethernet Header" << std::endl;
    std::cout << "Source MAC: " << ether_ntoa((const struct ether_addr *)eth_header->ether_shost) << std::endl;
    std::cout << "Destination MAC: " << ether_ntoa((const struct ether_addr *)eth_header->ether_dhost) << std::endl;

    // IP 패킷 확인
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // IP 헤더에서 출발지와 목적지 IP 주소 출력
        std::cout << "IP Header" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
    }

    std::cout << "-------------------------------------------" << std::endl;
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

//실시간 패킷 캡처 함수
int CFirewall::CapturePacket() {
    char chErrbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(m_chDevice , BUFSIZ, 1, 1000, chErrbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << m_chDevice << ": " << chErrbuf << std::endl;
        return 1; //에러 처리 하기
    }

    pcap_loop(handle, 0, CFirewall::packetHandler, nullptr);
    pcap_close(handle);
    pcap_freealldevs(m_pifAllDevices);

    return 0;
}
