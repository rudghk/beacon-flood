#ifndef MAC_H
#define MAC_H

#include <stdint.h>
#include <string>
#include <cstring>

struct Mac{
    uint8_t mac[6];

    Mac() {}
    Mac(const uint8_t* r) { memcpy(this->mac, r, 6); }
    Mac(const std::string& r) {
        std::string s;
        for(char ch: r) {
            if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
                s += ch;
        }
        int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (res != 6) {
            fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
            return;
        }
    }

    bool compare(Mac other){
        for(int i=0;i<sizeof(Mac);i++){
            if(this->mac[i]!=other.mac[i])
                return false;
        }
        return true;
    }

    std::string getMAC(){
        char buf[20]; // enough size
        sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    };
};

#endif
