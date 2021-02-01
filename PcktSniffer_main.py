import socket as sc
import textwrap
import PcktSniffer_func as sniff
import bcolors
import time
import struct

#Formating Constants
TAB_1 = "   - "
TAB_2 = "\t- "
TAB_3 = "\t    - "
TAB_4 = "\t\t- "
TAB_5 = "\t\t    - "
DATA_TABLE_PREF = "     |  "
DATA_TABLE_POST = "  |     "
DATA_TABLE_HORIZ = "     ======================================================================     "



class pcap:
    def __init__(self,name,datalink = 1):
        self.file = open(name + ".pcap",'wb')
        self.file.write(struct.pack('@ I H H i I I I',0xa1b2c3d4, 2, 4, 0, 0, 65535, datalink))

    def write(self, data):
        t_sec, t_usec = map(int, str(time.time()).split('.'))
        dlen = len(data)
        self.file.write(struct.pack('@ I I I I',t_sec,t_usec, dlen, dlen))
        self.file.write(data)

    def close(self):
        self.file.close()


def main():
    mainsc = sc.socket(sc.AF_PACKET, sc.SOCK_RAW, sc.ntohs(3))
    packet_counter = 1
    pcapfile = pcap("pcap_save")
    while True:
        try:
            raw_data, addr = mainsc.recvfrom(65535)
            pcapfile.write(raw_data)
            eth_dest_mac, eth_src_mac, eth_payload_type, eth_payload = sniff.Unpack_eth(raw_data)
            print(bcolors.HEADER + "Packet Number: {}".format(packet_counter) + bcolors.ENDC)
            packet_counter += 1
            print("Ethernet Frame:")
            print(TAB_1 + "Destination: {}, Source: {}, Type: {}".format(eth_dest_mac,eth_src_mac,eth_payload_type))
            print(TAB_1 + "Payload: ", end='')


            if eth_payload_type == 2048: #ethernet payload type is IPv4
                ip_version, ip_header_length, ip_ttl, ip_transportType, ip_src_ip, ip_dest_ip, ip_payload = sniff.Unpack_Ipv4(eth_payload)
                print(bcolors.BLUEHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "IPv4 Datagram:" + bcolors.ENDC)
                print(TAB_2 + "Version: {}, Internet Header Length: {} ({} Bytes)".format(ip_version,ip_header_length, ip_header_length*4))
                print(TAB_2 + "TTL: {}, Transport Protocol: {}".format(ip_ttl,ip_transportType))
                print(TAB_2 + "Source: {}, Destination: {}".format(ip_src_ip,ip_dest_ip))
                print(TAB_2 + "Payload: ",end='')


                if ip_transportType == 17: # Transport Layer is UDP
                    udp_src_port, udp_dest_port, udp_length, udp_payload = sniff.Unpack_UDP(ip_payload)
                    print(bcolors.YELLOWHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "User Datagram Protocol Segment:" + bcolors.ENDC)
                    print(TAB_3 + "Source Port: {}, Destination Port: {}, Length: {}".format(udp_src_port,udp_dest_port,udp_length))
                    print(TAB_3 + "Payload: ",end='')

                    if(udp_src_port == 53 or udp_dest_port == 53): # Application Layer is DNS
                        print(bcolors.BLUE + bcolors.BOLD + "DNS Message:" + bcolors.ENDC)
                        dns_identification,dns_QR_flag,dns_opcode,dns_AA_flag,dns_TC_flag,dns_RD_flag,dns_RA_flag,dns_Z_flag,\
                        dns_AD_flag,dns_CD_flag,dns_rcode, dns_questions_count,dns_answers_count,dns_authorityRRs_count,\
                        dns_aditionalRRs_count,dns_data = sniff.Unpack_DNS(udp_payload)
                        print(TAB_4 + "Identification: {}, QR: {}, Opcode: {}".format(dns_identification,dns_QR_flag,dns_opcode))
                        print(TAB_4 + "Flags:\n{}AA: {}, TC: {}, RD: {}, RA: {}".format(TAB_5, dns_AA_flag,dns_TC_flag,dns_RD_flag,dns_RA_flag))
                        print("{}Z: {}, AD: {}, CD: {}".format(TAB_5, dns_Z_flag, dns_AD_flag, dns_CD_flag))
                        print(TAB_4 + "Rcode: {}".format(dns_rcode))
                        print(TAB_4 + "Total Questions: {}, Total Answers: {}".format(dns_questions_count,dns_answers_count))
                        print(TAB_4 + "Total Authority RRs: {}, Total Additional RRs: {}".format(dns_authorityRRs_count, dns_aditionalRRs_count))
                        print(TAB_4 + "Rest of Data:")
                        print(DATA_TABLE_HORIZ,end='')
                        print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,dns_data))
                        print(DATA_TABLE_HORIZ)

                    elif(udp_src_port == 80 or udp_dest_port == 80): # Application Layer is HTTP
                        print(bcolors.GREEN + bcolors.BOLD + "HTTP Message:" + bcolors.ENDC)
                        http_header, http_data = sniff.Unpack_HTTP(udp_payload)
                        print(TAB_4 + "Header:")
                        print(MultiLine_Prefix(TAB_4,http_header))
                        print(TAB_4 + "Data:")
                        if http_data:
                            print(DATA_TABLE_HORIZ,end='')
                            print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,http_data))
                            print(DATA_TABLE_HORIZ)
                        else: print(bcolors.RED + TAB_5 + "Empty!" + bcolors.ENDC)
                    
                    else: # Application Layer is Unknown
                        print(bcolors.RED + bcolors.BOLD + "Unknown Message:" + bcolors.ENDC)
                        print(DATA_TABLE_HORIZ,end='')
                        print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,udp_payload))
                        print(DATA_TABLE_HORIZ)


                elif ip_transportType == 6: # Transport Layer is TCP
                    src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
                    PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size, checksum, urg_pointer,tcp_payload = sniff.Unpack_TCP(ip_payload)
                    print(bcolors.GREENHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "Transmission Control Protocol Segment:" + bcolors.ENDC)
                    print(TAB_3 + "Source Port: {}, Destination Port: {}".format(src_port,dest_port))
                    print(TAB_3 + "Sequence Number: {}".format(sqnc_num))
                    print(TAB_3 + "Acknowledgement Number: {}".format(ack_num))
                    print(TAB_3 + "Data Offset: {} ({} Bytes)".format(data_offset,data_offset*4))
                    print(TAB_3 + "Flags:\n {}NS: {}, CWR: {}, ECE: {}, URG: {}, ACK: {}".format(TAB_4,NS_flag,CWR_flag,ECE_flag,URG_flag,ACK_flag))
                    print("{}PSH: {}, RST: {}, SYN: {}, FIN: {}".format(TAB_4,PSH_flag,RST_flag,SYN_flag,FIN_flag))
                    print(TAB_3 + "Window Size: {}, Checksum: {}, Urgent Pointer: {}".format(window_size, checksum, urg_pointer))
                    print(TAB_3 + "Payload: ",end='')

                    if(tcp_payload):
                        if(src_port == 53 or dest_port == 53): # Application Layer is DNS
                            print(bcolors.BLUE + bcolors.BOLD + "DNS Message:" + bcolors.ENDC)
                            dns_identification,dns_QR_flag,dns_opcode,dns_AA_flag,dns_TC_flag,dns_RD_flag,dns_RA_flag,dns_Z_flag,\
                            dns_AD_flag,dns_CD_flag,dns_rcode, dns_questions_count,dns_answers_count,dns_authorityRRs_count,\
                            dns_aditionalRRs_count,dns_data = sniff.Unpack_DNS(tcp_payload)
                            print(TAB_4 + "Identification: {}, QR: {}, Opcode: {}".format(dns_identification,dns_QR_flag,dns_opcode))
                            print(TAB_4 + "Flags:\n{}AA: {}, TC: {}, RD: {}, RA: {}".format(TAB_5, dns_AA_flag,dns_TC_flag,dns_RD_flag,dns_RA_flag))
                            print("{}Z: {}, AD: {}, CD: {}".format(TAB_5, dns_Z_flag, dns_AD_flag, dns_CD_flag))
                            print(TAB_4 + "Rcode: {}".format(dns_rcode))
                            print(TAB_4 + "Total Questions: {}, Total Answers: {}".format(dns_questions_count,dns_answers_count))
                            print(TAB_4 + "Total Authority RRs: {}, Total Additional RRs: {}".format(dns_authorityRRs_count, dns_aditionalRRs_count))
                            print(TAB_4 + "Rest of Data:")
                            print(DATA_TABLE_HORIZ,end='')
                            print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,dns_data))
                            print(DATA_TABLE_HORIZ)

                        elif(src_port == 80 or dest_port == 80): # Application Layer is HTTP
                            print(bcolors.GREEN + bcolors.BOLD + "HTTP Message:" + bcolors.ENDC)
                            http_header, http_data = sniff.Unpack_HTTP(tcp_payload)
                            print(TAB_4 + "Header:")
                            print(MultiLine_Prefix(TAB_4,http_header))
                            print(TAB_4 + "Data:")
                            if http_data:
                                print(DATA_TABLE_HORIZ,end='')
                                print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,http_data))
                                print(DATA_TABLE_HORIZ)
                            else: print(bcolors.RED + TAB_5 + "Empty!" + bcolors.ENDC)
                        
                        
                        else: # Application Layer is Unknown
                            print(bcolors.RED + bcolors.BOLD + "Unknown Message:" + bcolors.ENDC)
                            print(DATA_TABLE_HORIZ,end='')
                            print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,tcp_payload))
                            print(DATA_TABLE_HORIZ)
                    else: print(bcolors.RED + "Empty!" + bcolors.ENDC)
                elif ip_transportType == 1: # Transport Layer is ICMP
                    icmp_type, icmp_code, icmp_cheksum, icmp_rest_data = sniff.Unpack_ICMP(ip_payload)
                    print(bcolors.WHITEHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "Internet Control Message Protocol Segment:" + bcolors.ENDC)
                    print(TAB_3 + "Type: {}, Code{}, Checksum: {}".format(icmp_type,icmp_code,icmp_cheksum))
                    print(TAB_3 + "Rest of Header and Data:")
                    print(icmp_rest_data)

                else: #Unknown Transport Layer
                    print(bcolors.REDHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "Unknown Transport Layer Protocol:" + bcolors.ENDC)
                    print(TAB_3 + "Raw IPv4 Payload:")
                    print(DATA_TABLE_HORIZ,end='')
                    print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,ip_payload))
                    print(DATA_TABLE_HORIZ)

            elif eth_payload_type == 2054: #ethernet palyoad type is ARP
                arp_hardware_type, arp_protocol_type, arp_hardware_size, arp_protocol_size, arp_opcode, arp_src_mac,\
                arp_src_ipv4, arp_dest_mac, arp_dest_ipv4 = sniff.Unpack_ARP(eth_payload)
                print(bcolors.GRAYHIGHLIGHT + bcolors.BOLD + "Address Resolution Protocol Datagram:" + bcolors.ENDC)
                print(TAB_2 + "Hardware Type: {}, Protocol Type: {}".format(arp_hardware_type,arp_protocol_type))
                print(TAB_2 + "Hardware Size: {}, Protocol Size: {}, Opcode: {}".format(arp_hardware_size,arp_protocol_size,arp_opcode))
                print(TAB_2 + "Sender MAC: {}, Sender IP: {}".format(arp_src_mac,arp_src_ipv4))
                print(TAB_2 + "Target MAC: {}, Target IP: {}".format(arp_dest_mac,arp_dest_ipv4))


            else: #ethernet payload Type unknown
                print(bcolors.REDHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "Unknown Network Layer Type:" + bcolors.ENDC)
                print(TAB_2 + "Raw Ethernet Payload:")
                print(DATA_TABLE_HORIZ,end='')
                print(Format_MultiLine(DATA_TABLE_PREF,DATA_TABLE_POST,eth_payload))
                print(DATA_TABLE_HORIZ)
            print("\n--------------------------------------------------------------------------------\n")
        except KeyboardInterrupt:
            pcapfile.close()
            print(bcolors.REDHIGHLIGHT + bcolors.BLACK + bcolors.BOLD + "Capture Stoped" + bcolors.ENDC)
            break




# Format Raw data to be More Readable
def Format_MultiLine(prefix,postfix,data,size=80):
    size -= len(prefix) + len(postfix)
    if isinstance(data, bytes):
        data = ''.join(r'\x{:02x}'.format(byte) for byte in data)
        if size % 2 : size -= 1
    return '\n'.join([prefix + line + postfix for line in textwrap.wrap(data,size) ])


# Atach Prefix to Every Line of a String
def MultiLine_Prefix(prefix,string):
    string = string.split('\n')
    return '\n'.join([prefix + line for line in string[:-1]])




main()
