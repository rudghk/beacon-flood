#ifndef DOT11_H
#define DOT11_H

#include <stdint.h>
#include "mac.h"

struct RadiotapHdr{ // 8 bytes
    uint8_t revision;
    uint8_t pad;
    uint16_t len;   // radiotap total size
    uint32_t present;

    void setDefault(){
        this->revision = 0x00;
        this->pad = 0x00;
        this->len = 0x000c;
        this->present = 0x00008004;
    }
};

struct Dot11Hdr{
    uint8_t version:2;    // 2bit
    uint8_t type:2;       // 2bit
    uint8_t subtype:4;    // 4bit
    uint8_t flag;
    uint16_t duration;
    Mac addr1;
    Mac addr2;
    Mac addr3;
    uint16_t seqControl;

    void setDefaultBeacon(Mac ap, Mac station){
        this->version = 0x00;
        this->type = 0x00;
        this->subtype = 0x08;
        this->flag = 0x00;
        this->duration = 0x0000;
        if(station.compare(Mac("00:00:00:00:00:00"))) // station이 NULL인 경우
            station = Mac("FF:FF:FF:FF:FF:FF");    // broadcast
        if(ap.compare(Mac("00:00:00:00:00:00"))) // ap가 NULL인 경우
            ap = Mac("00:11:22:33:44:55");
        this->addr1 = station;  // ra
        this->addr2 = ap;    // ta
        this->addr3 = ap;    // bssid
        this->seqControl = 0x0000;
    }
};

#endif
