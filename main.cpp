#include "main.hpp"

CFirewall Ifirewall;


int main(){

    // Ifirewall.RunFirewall();

    Ifirewall.SelectData();
    Ifirewall.GetDeviceName();
    Ifirewall.RunFirewall();

    
    return 0;
}