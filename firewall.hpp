#pragma once
#include "ini.hpp"
#include "configDB.hpp"

#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>

class CFirewall {
    public:
        pcpp::PcapLiveDevice* GetDeviceName();
};