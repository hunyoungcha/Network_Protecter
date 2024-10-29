#include "firewall.hpp"

void packetArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* userData) {
    // RawPacket을 Packet 객체로 변환
    pcpp::Packet parsedPacket(rawPacket);

    // IP 레이어가 존재하는지 확인하고 출력
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer != nullptr) {
        std::cout << "Source IP: " << ipLayer->getSrcIPAddress().toString() 
                  << " -> Destination IP: " << ipLayer->getDstIPAddress().toString() << std::endl;
    }

    // TCP 레이어가 존재하는지 확인하고 출력
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer != nullptr) {
        std::cout << "TCP Port: " << tcpLayer->getTcpHeader()->portSrc << " -> "
                  << tcpLayer->getTcpHeader()->portDst << std::endl;
    }
}

pcpp::PcapLiveDevice* CFirewall::GetDeviceName(){
    std::vector<pcpp::PcapLiveDevice*> vecDevices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    if (vecDevices.empty()) {
        std::cerr << "사용 가능한 네트워크 디바이스가 없습니다." << std::endl;
        return nullptr;
    }

    std::cout << "사용 가능한 네트워크 디바이스 목록:" << std::endl;
    for (size_t i = 0; i < vecDevices.size(); ++i) {
        std::cout << i << ": " << vecDevices[i]->getName() 
                  << " (" << vecDevices[i]->getIPv4Address().toString() << ")" << std::endl;
    }


    int deviceIndex = -1;
    std::cout << "캡처할 네트워크 디바이스 번호를 선택하세요: ";
    std::cin >> deviceIndex;

    if (deviceIndex < 0 || deviceIndex >= vecDevices.size()) {
        std::cerr << "잘못된 번호를 입력했습니다." << std::endl;
        return nullptr;
    }

    return vecDevices[deviceIndex];
}
