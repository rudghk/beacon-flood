#ifndef BEACON_H
#define BEACON_H

#include "dot11.h"

#pragma pack(push, 1)
struct BeaconFixedData{  // 12 bytes
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capacity;

    void setDefualt(){
        this->timestamp = 0x0;
        this->interval = 0x0064;
        this->capacity = 0x0001;
    }
};
#pragma pack(pop)

struct TagParm{
    uint8_t tag;    // ssid == 0x00
    uint8_t len;

    void* value(){
        return (char*)this+sizeof(TagParm);
    }

    TagParm* next(){
        char* res = (char*)this;
        res += sizeof(TagParm)+this->len;
        return (TagParm*) res;
    }
    void set(uint8_t tag, uint8_t len){
        this->tag = tag;
        this->len = len;
    }
};

struct BeaconHdr{
    RadiotapHdr radiotapHdr;    // 8 bytes
    Dot11Hdr dot11Hdr;      // 24 bytes
    BeaconFixedData fixed;
    TagParm* tagParm;

    void setDot11Hdr() {
        // Dot11Hdr
        char* res = (char*)this;
        res += this->radiotapHdr.len;
        this->dot11Hdr = *(Dot11Hdr*)res;
        // BeaconFixedData
        res += sizeof(Dot11Hdr);
        this->fixed = *(BeaconFixedData*)res;
        // TagParm
        res += sizeof(BeaconFixedData);
        this->tagParm = (TagParm*)res;
    }

    Mac getBSSID(){
        return this->dot11Hdr.addr3;
    }
};

#endif

