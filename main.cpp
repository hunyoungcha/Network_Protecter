#include "main.hpp"


int main(){
    CConfigDB IConfigDB;
    CFirewall IFirewall(IConfigDB);

    // Ifirewall.RunFirewall();

    IFirewall.GetDeviceName();
    IFirewall.RunFirewall();

    
    return 0;
}