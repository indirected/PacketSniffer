import struct
import sys



# Unpack the ethernet frame and return header,data
# implemented according to https://en.wikipedia.org/wiki/Ethernet_frame
def Unpack_eth(data):
    dest_mac, src_mac, networkType = struct.unpack('! 6s 6s H',data[:14])
    return Make_mac_readable(dest_mac), Make_mac_readable(src_mac) , networkType, data[14:]

def Make_mac_readable(mac):
    s = map('{:02x}'.format,mac)
    return ':'.join(s).upper()  



# Unpack Ipv4 Datagram and return header,data
# implemented according to https://en.wikipedia.org/wiki/IPv4
def Unpack_Ipv4(data):
    firstbyte = data[0]
    version = firstbyte >> 4
    header_length = (firstbyte & 15) #IHL shows the count of 4 Byte Lines in header
    ttl, transportType, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl, transportType, Make_ipv4_readable(src_ip), Make_ipv4_readable(dest_ip), data[header_length*4:]

def Make_ipv4_readable(ip):
    return '.'.join(map(str, ip))




# Unpack ARP Datagram and return ARP data
# implemented according to https://en.wikipedia.org/wiki/Address_Resolution_Protocol
# in this function i assumed that ARP protocol type is IPv4
def Unpack_ARP(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ipv4,\
    dest_mac, dest_ipv4 = struct.unpack('! H H B B H 6s 4s 6s 4s',data[:28])
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, Make_mac_readable(src_mac),\
    Make_ipv4_readable(src_ipv4), Make_mac_readable(dest_mac), Make_ipv4_readable(dest_ipv4)



# Unpack ICMP Segment and return ICMP data
# implemented according to https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
def Unpack_ICMP(data):
    icmp_type, icmp_code, icmp_cheksum = struct.unpack('! B B H',data[:4])
    return icmp_type, icmp_code, icmp_cheksum, data[4:]



# Unpack UDP segment and return header,data
# implemented according to https://en.wikipedia.org/wiki/User_Datagram_Protocol
def Unpack_UDP(data):
    src_port, dest_port, length = struct.unpack('! H H H',data[:6])
    return src_port, dest_port, length, data[8:]




# Unpack TCP segment and return header,data
# implemented according to https://en.wikipedia.org/wiki/Transmission_Control_Protocol
def Unpack_TCP(data):
    src_port, dest_port, sqnc_num, ack_num, byte1314, window_size, checksum, urg_pointer = struct.unpack('! H H L L H H H H', data[:20])
    data_offset = (byte1314 >> 12)
    NS_flag = (byte1314 & 256) >> 8
    CWR_flag = (byte1314 & 128) >> 7
    ECE_flag = (byte1314 & 64) >> 6
    URG_flag = (byte1314 & 32) >> 5
    ACK_flag = (byte1314 & 16) >> 4
    PSH_flag = (byte1314 & 8) >> 3
    RST_flag = (byte1314 & 4) >> 2
    SYN_flag = (byte1314 & 2) >> 1
    FIN_flag = (byte1314 & 1)
    #if len(data) > data_offset*4:
    return src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
        PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size, checksum, urg_pointer,data[data_offset*4:]
    # else:
    #     return src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
    #         PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size, checksum, urg_pointer


# Unpack and decode DNS message and return data
# implemented according to https://en.wikipedia.org/wiki/Domain_Name_System
# Data Parsing is halfway so im gonna ignore it for now
def Unpack_DNS(data):
    #questions = []
    identification, bytes34, questions_count, answers_count, authorityRRs_count, aditionalRRs_count = struct.unpack('! H H H H H H',data[:12])
    QR_flag = bytes34 >> 15
    opcode = (bytes34 & 30720) >> 11
    AA_flag = (bytes34 & 1024) >> 10
    TC_flag = (bytes34 & 512) >> 9
    RD_flag = (bytes34 & 256) >> 8
    RA_flag = (bytes34 & 128) >> 7
    Z_flag = (bytes34 & 64) >> 6
    AD_flag = (bytes34 & 32) >> 5
    CD_flag = (bytes34 & 16) >> 4
    rcode = bytes34 & 15
    return identification,QR_flag,opcode,AA_flag,TC_flag,RD_flag,RA_flag,Z_flag,AD_flag,CD_flag,rcode,\
            questions_count,answers_count,authorityRRs_count,aditionalRRs_count,data[12:]
    #TODO: DNS Parsing
    #dataindex = 12
    # for i in range(0,questions_count):
    #     Qname = ""
    #     while True:
    #         preflen = struct.unpack('! B',data[dataindex:dataindex+1])
    #         preflen = preflen[0]
    #         #print(preflen)
    #         dataindex += 1
    #         if preflen == 0: break
    #         formatstr = '! ' + str(preflen) + 's'
    #         tmpchars = struct.unpack(formatstr,data[dataindex: dataindex + preflen])
    #         dataindex += preflen
    #         #strrrr = ''.join(map(str(),tmpchars))
    #         #strrrr = ''.join([str(x,"utf-8") for x in tmpchars])
    #         Qname += ''.join([str(x,"utf-8") for x in tmpchars]) + '.'
    #     Qname = Qname[:-1]
    #     #print(Qname)
    #     Qtype, Qclass = struct.unpack('! H H',data[dataindex:dataindex+4])
    #     dataindex += dataindex + 4
    #     #print(Qtype)
    #     #print(Qclass)
    #     questions.append([Qname,Qtype,Qclass])
    # for i in range (0,answers_count):
    #     name = ""
    #     while True:
    #         preflen = struct.unpack('! B',data[dataindex:dataindex+1])
    #         preflen = preflen[0]
    #         dataindex += 1
    #         if preflen == 0: break
    #         formatstr = '! ' + str(preflen) + 's'
    #         tmpchars = struct.unpack(formatstr,data[dataindex: dataindex + preflen])
    #         dataindex += preflen
    #         Qname += ''.join([str(x,"utf-8") for x in tmpchars]) + '.'
    #     Qname = Qname[:-1]
    #     #print(Qname)
    #     Qtype, Qclass = struct.unpack('! H H',data[dataindex:dataindex+4])
    #     dataindex += dataindex + 4
    #     #print(Qtype)
    #     #print(Qclass)
    #     questions.append([Qname,Qtype,Qclass])





# Unpacks HTTP message and return header, content
# Reads Only the header at this moment
def  Unpack_HTTP(data):
    #print(data)
    headerend = data.rfind(b'\r\n')
    #print(headerend)
    #print(str(data[:headerend],"ascii"))
    header = str(data[:headerend],"ascii")
    #TODO: HTTP Parsing
    # charset_index = header.find('charset=')
    # if charset_index > 0:
    #     charset_index += 8
    #     #print(charset_index)
    #     #print(header[charset_index])
    #     charset_str = ""
    #     while True:
    #         if(header[charset_index] == '\r'): break
    #         charset_str += header[charset_index]
    #         charset_index += 1
    #     #print(charset_str)
        
        
    # content = ""
    # if sys.getsizeof(data) > headerend + 2:
    #     #print(str(data[headerend -10:headerend+3],'ascii'))
    #     content = data[headerend + 2:]
    # #print(content)

    return header,data[headerend+2:]
