#include <stdio.h>
#include <pcap.h>               // pcap lib 헤더, 패킷 캡처 및 네트워크 분석 기능 제공
#include <arpa/inet.h>          // IP 주소 처리 함수 제공
#include <netinet/if_ether.h>   // Ethernet 프레임 처리를 위한 함수 및 구조체 정의
#include <netinet/ip.h>         // IP 패킷 처리를 위한 구조체 정의 
#include <netinet/tcp.h>        // TCP 세그먼트 처리를 위한 구조체 정의 

// 패킷 캡쳐시 호출되는 콜백 함수 정의
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 캡처된 패킷에서 Ethernet 헤더 추출
    const struct ether_header *eth = (struct ether_header *)packet;

    // Ethernet 헤더에서 소스 및 목적지 MAC 주소를 추출하고, 사람이 읽을 수 있는 형태로 변환하여 출력
    printf("Src MAC: %s, Dst MAC: %s\n", ether_ntoa((struct ether_addr *)&eth->ether_shost), ether_ntoa((struct ether_addr *)&eth->ether_dhost));

    // 패킷이 IP 패킷인지 확인 (Ethernet Type이 IP인 경우)
    if (ntohs(eth->ether_type) == 0x0800) {
        // Ethernet 헤더 이후의 데이터에서 IP 헤더 추출
        const struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));

        // IP 헤더에서 소스 및 목적지 IP 주소 추출 및 출력
        printf("From: %s, To: %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

        // 패킷이 TCP 프로토콜을 사용하는지 확인
        if (ip->ip_p == IPPROTO_TCP) {
            // IP 헤더 이후의 데이터에서 TCP 헤더 추출
            const struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);

            // TCP 헤더에서 소스 및 목적지 포트 번호 추출 및 출력
            printf("Protocol: TCP, Src port: %d, Dst port: %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

            // TCP 페이로드 크기 계산->len 이용
            int ip_header_len = ip->ip_hl * 4;
            int tcp_header_len = tcp->th_off * 4;
            int payload_len = ntohs(ip->ip_len) - ip_header_len - tcp_header_len;
            // TCP 페이로드 시작 위치 계산
            const char *payload = (const char *)(packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len);

            // 페이로드가 존재하면, 16진수 형태로 출력
            if (payload_len > 0) {
                printf("Payload (%d bytes):\n", payload_len);
                for(int i = 0; i < payload_len; i++) {
                    printf("%02x ", (unsigned char)payload[i]);
                    if ((i + 1) % 16 == 0) printf("\n"); // 16바이트마다 줄바꿈
                }
                printf("\n\n");
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지를 저장하기 위한 버퍼
    pcap_t *handle; // 패킷 캡처 세션 핸들

    // 지정된 네트워크 인터페이스에서 패킷 캡처를 위한 pcap 세션을 엽니다.
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device ens33: %s\n", errbuf);
        return 2;
    }

    // TCP 패킷만 캡처하기 위한 패킷 필터링
    struct bpf_program fp;
    char filter_exp[] = "tcp"; //tcp만 필터링
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) { //필터 적용
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle); // 필터 적용 실패시 세션 종료
        return 2;
    }

    // 무한 루프 내에서 패킷 캡처 시작, 새로운 패킷이 캡처될 때마다 got_packet 콜백 함수 호출
    pcap_loop(handle, -1, got_packet, NULL);

    // 모든 작업 완료 후 pcap 세션 닫기
    pcap_close(handle);
    return 0;
}