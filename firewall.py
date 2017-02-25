#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
import collections
import random
# Authors: Allan Peng, Owen Chen

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        rules = open(config['rule'], "r")
 
        self.firewall_rules = []
        self.countryRules = {}
        self.countryCodes = set()
        self.log_rules = []
        self.http_logs = {}
        for rule in rules:
            #Get rid of all \n
            strip = rule.rstrip()
            #Parse each rule by word
            rule_list = strip.split(" ")
 
            #If first letter is a comment or empty rule
            if rule_list[0] == "%" or rule_list[0] == '':
                continue
            seen_http = False
            # log http
            if rule_list[0].lower() == "log" and rule_list[1].lower()== "http":
                seen_http = True
                self.log_rules.append(rule_list[2].lower())
 
            #Protocol/IP/Port Rule
            elif rule_list[1].lower() != "dns":
 
                rule_format = [rule_list[0].upper(), rule_list[1].upper(), rule_list[2].upper(), rule_list[3].upper()]
            # DNS rule
            elif rule_list[1].lower() == "dns":
 
                rule_format = [rule_list[0].upper(), rule_list[1].upper(), rule_list[2].upper()]
 
            #If rule_List[2] is a country code, append it to self.countryCodes
            if len(rule_list[2]) ==2 and rule_list[2].isalpha():
                self.countryCodes.add(rule_list[2].upper())
            if not seen_http:
                self.firewall_rules.append(rule_format)
        log_buffer.log_rules = self.log_rules
        geodb = open("geoipdb.txt", "r")
        pattern = ""
        for i in self.countryCodes:
            #regex to search.
            pattern += '(' + i + ')' + "|"
        pattern = pattern[:len(pattern)-1]
        for geo in geodb:
            geo = geo.rstrip()
            if not re.search(pattern, geo):
                continue
            geo = geo.split(" ")
 
            start = struct.unpack("!I", socket.inet_aton(geo[0]))[0]
            end = struct.unpack("!I", socket.inet_aton(geo[1]))[0]
            country = geo[2].upper()
            if self.countryRules.get(country) == None:
                self.countryRules[country] = []
            ipRange = (start, end)
            self.countryRules[country].append(ipRange)
 
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
 
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'
        length = struct.unpack("!H" ,pkt[2:4])[0]
        num_lines = struct.unpack('!B',pkt[0]) [0] & 0xf
        #this is wrong. check later.
        if num_lines < 5: return
        if len(pkt) != length:
            return
        Transfer, bytes_in_packet, source_address, \
            dest_address = self.parse_ip(pkt[0 : 4 * num_lines])
        datagram = pkt[4*num_lines:]
        verdict, deny =  self.can_send(pkt_dir, datagram, dest_address, Transfer, bytes_in_packet, source_address)
 
        log = False
 
        #iterate through log rules here.
        if Transfer == "TCP":
 
            source_port, dest_port = self.parse_tcp(datagram)
 
            if pkt_dir == PKT_DIR_INCOMING:
                port = source_port
                ext_addr = dest_address
                internal_port = dest_port
            else:
                port = dest_port
                ext_addr = source_address
                internal_port = source_port
 
            if port == 80:
                ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4
                tcp_header_size = (ord(struct.unpack("!s", pkt[ihl + 12])[0]) >> 4) * 4

                offset = ihl + tcp_header_size
                ack_byte = struct.unpack("!B", datagram[13])[0]
                syn = bool((ack_byte>>1)&1)
                ack = bool((ack_byte>>4)&1)
                seqno = struct.unpack("!I", datagram[4:8])[0]
                http_data = pkt[offset:]
                self.do_log_shit(ext_addr, http_data, pkt_dir, internal_port, seqno, syn, ack)
 
        if verdict:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
 
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
 
        elif deny:
            if Transfer == "TCP":
                source_port, dest_port = self.parse_tcp(datagram)
                rst_pkt = self.create_tcp_packet(pkt, source_address, dest_address, source_port, dest_port)
                if pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_int.send_ip_packet(rst_pkt)
                elif pkt_dir == PKT_DIR_INCOMING:
                    self.iface_ext.send_ip_packet(rst_pkt)
            elif Transfer == "UDP":
                is_dns, domain = self.parse_dns(datagram)
                dns_packet = self.create_DNS_deny(pkt, domain)
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_ext.send_ip_packet(dns_packet)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_int.send_ip_packet(dns_packet)
            else:
                raise Exception
        else:
            pass
 
    def can_send(self, pkt_dir, datagram, dest_address, Transfer, bytes_in_packet, source_address):
        verdict = True
        is_dns = None
        port = None
        deny = False
        if not (Transfer == "UDP" or Transfer == "TCP" or Transfer == "ICMP"):
            return True
 
        #do DNS shit once so we don't do it again.
        if not (Transfer == "UDP" and pkt_dir == PKT_DIR_OUTGOING):
            is_dns = False
        else:
            srcPort, dstPort = self.parse_udp(datagram)
            if dstPort != 53: is_dns = False
            else:
                is_dns, server = self.parse_dns(datagram)
 
        #Linear scan through the rules
        for rule in self.firewall_rules:
            #Non-DNS
            if rule[1] != "DNS":
 
                if rule[1] != Transfer:
                    continue
                else:
                    if Transfer == "UDP":
 
                        if len(datagram) < 8:
                            return False
                        source_port, dest_port = self.parse_udp(datagram)
                        if pkt_dir == PKT_DIR_INCOMING:
                            port = source_port
                        else:port = dest_port
 
                    if Transfer == "TCP":
                        if len(datagram) < 20: return False
                        source_port, dest_port = self.parse_tcp(datagram)
                        if pkt_dir == PKT_DIR_INCOMING:
                            port = source_port
                        else:
                            port = dest_port
                    if Transfer == "ICMP":
                        if len(datagram) < 8: return False
                        type_message = self.parse_icmp(datagram)
                        port = type_message
                    if pkt_dir == PKT_DIR_OUTGOING:
                        do_verdict = self.applicable_rule(rule, dest_address, port)
                    elif pkt_dir == PKT_DIR_INCOMING:
                       do_verdict = self.applicable_rule(rule, source_address, port)
                    if do_verdict:
                        #Drop
                        if rule[0] == "DROP":
                            verdict = False
                        if rule[0] == "DENY":
                            verdict = False
                            deny = True
                        if rule[0] == "PASS":
                            verdict = True
                            deny = False
 
            elif rule[1] == "DNS" and is_dns:
                #print("parsing dns")
 
                does_apply = False
                dns_domain_list = rule[2].lower()
                # Check if the DNS rule has an asterisk
                if "*" in dns_domain_list:
                    if dns_domain_list[0] != "*":
                        # The rule is bad, continue to next rule
                        continue
                    else:
                        checker = len(dns_domain_list)-1
                        if len(server) <= checker: continue
                        does_apply = dns_domain_list[1:]==server[-checker:]
                else:
                    does_apply = dns_domain_list == server
                if does_apply:
                    #Do the verdict of the DNS
                    if rule[0] == "DROP":
                        verdict = False
                    if rule[0] == "PASS":
                        verdict = True
                        deny = False
                    if rule[0] == "DENY":
                        verdict = False
                        deny = True
        return (verdict, deny)
 
    def applicable_rule(self, rule, dest_address, port):
        #Used to see if we should apply the verdict
        result = self.valid_ip(rule, dest_address) and self.valid_port(rule, port)
        return result
 
    def in_range(self, a, inRange):
        return a <= inRange[1] and a >= inRange[0]
 
    #returns True if IP_address belongs to country.
    def in_country(self,a, country):
        country = self.countryRules[country]
        minimum = 0
        maximum = len(country)
        while minimum < maximum:
            i = (minimum + maximum)/2
            if self.in_range(a, country[i]):
                return True
            if country[i][0] >  a:
                maximum = i -1
            elif country[i][0] < a:
                minimum = i +1
 
        return False
    #Rule list, IP Address
    def valid_ip(self, rule, address):
        #don't forget drop.
        #Any
        if rule[2] == "ANY":
            return True
        #2 byte country code
        if len(rule[2]) == 2:
            return self.in_country(address, rule[2])
 
        #IP prefix
        elif "/" in rule[2]:
            slash_notation = rule[2].split('/')
            #Number of IP's from slash notation
            rightShift = int(slash_notation[1]) -32
            a = slash_notation[0].split(".")
            #Right shift rule address and packet address
            ruleBinary = 0
            for i in range(4):
                ruleBinary += int(a[i])* pow(256,3-i)
            ruleBinary = bin(ruleBinary)[:rightShift]
            addressBinary = bin(address)[:rightShift]
            return ruleBinary == addressBinary
        convert = rule[2].split(".")
        check = 0
        for i in range(4):
            check += int(convert[i]) * pow(256, 3-i)
        return address == check
 
    #this should work.
    def valid_port(self, rule, port):
        #Any
        if rule[3] == "ANY":
            return True
        #Range
        elif "-" in rule[3]:
            #This is a range.
            port_range = rule[3].split("-")
            #Do shit here
            return int(port) >= int(port_range[0]) and int(port) <= int(port_range[1])
 
        elif int(rule[3]) == int(port):
            return True
        return False
 
    def parse_ip(self, header):
        Protocol = struct.unpack("!B", header[9])[0]
        bytes_in_packet = struct.unpack("!H",header[2:4])[0]
        source_address = struct.unpack ("!I", header[12:16])[0]
        dest_address = struct.unpack("!I", header[16:20])[0]
        Transfer = None
        if Protocol == 01:
            Transfer = "ICMP"
        elif Protocol == 0x06:
            Transfer = "TCP"
        elif Protocol == 0x11:
            Transfer = "UDP"
        return (Transfer, bytes_in_packet, source_address, dest_address)
 
    def parse_tcp(self, header):
        source_port = struct.unpack("!H", header[0:2])[0]
        dest_port = struct.unpack("!H", header[2:4])[0]
        return (source_port, dest_port)
 
    def parse_icmp(self, header):
        return struct.unpack("!B", header[0])[0]
 
    def parse_udp(self, header):
        source_port = struct.unpack("!H", header[0:2])[0]
        dest_port = struct.unpack("!H", header[2:4])[0]
        return (source_port, dest_port)
 
    #returns true if it's a DNS packet.
    def parse_dns(self, datagram):
        # DNS packet must have QDCOUNT set to 1 to be considered DNS
        #8 Bytes header
        if len(datagram) < 12: return (False, None)
        udp_size = struct.unpack('!H', datagram[4:6])[0]
        if udp_size != len(datagram):
            #print "malformed"
            return (False, None)
        datagram = datagram[8:]
 
        dns_qcount = struct.unpack("!H", datagram[4:6] )[0]
        #print dns_qcount
        if dns_qcount != 1: return (False, None)
 
        i = 12
        search = struct.unpack("!B", datagram[i])[0]
        j = 0
        domain = ""
 
        while i < len(datagram) and ord(datagram[i]) != 0:
            if j <= search and j > 0:
                domain += chr(struct.unpack("!B", datagram[i])[0])
                j+=1
            elif j == 0:
                #print "starting"
                #print search
                search = struct.unpack("!B", datagram[i])[0]
                domain += "."
                j +=1
 
            if j > search:
                j = 0
            i += 1
        qtype = struct.unpack('!H', datagram[i+1:i+3])[0]
        qclass = struct.unpack('!H', datagram[i+3:i+5])[0]
        domain = domain[1:]
 
        datagram =  datagram[i:]
        if  len(datagram)<4: 
            return (False, None)
 
        if not (qtype == 1 or qtype == 28):
            return (False, None)
 
        if qclass != 1: return (False, None)
        #print "This is DNS"
 
        return (True, domain)
 
    #creates an IP header
    def create_ip_header(self, protocol, source_address, dest_address):
        version = 4
        #IHL
        header_length = 5
        #default TOS is 0
        TOS = 0
        #Number of bytes in ENTIRE IP Packet
        #5 * 4 in header. 5*4 in TCP header + 0 im the message = 40
        packet_length = 40
        #Identification, flags, fragment offset. Just set these to 0
        this_shit = 0
        #TTL = 64
        TTL = 64
 
        if protocol == "TCP":
            Prot = 6
        elif protocol == "UDP":
            Prot = 17
        else:
            raise Exception
        # 16 bit half- words
        hw1 = ((version << 4)|header_length) << 8 + TOS
        hw2 = packet_length
        hw3 = 0
        hw4 = 0
        hw5 = (TTL << 8 ) | Prot
        #hw6 = checksum
        hw7 = source_address// pow(2,8)
        hw8 = source_address &0xff
        hw9 = dest_address // pow(2.8)
        hw10 = dest_address & 0xff
        #checksum
        hw6 = self.ip_checksum(list(hw1, hw2, hw3, hw4, hw5, hw7, hw8, hw9, hw10))
        retval = struct.pack("!HHHHH", hw1, hw2, hw3, hw4, hw5)
        retval += hw6
        retval += struct.pack("!HHHH", hw7, hw8, hw9, hw10)
        return retval
 
    #creates a TCP RST packet.
    def create_tcp_packet(self, pkt, source_addr, dest_addr, source_port, dest_port):
        # IP header
        ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4
        tcp_rst = struct.pack('!L', 0x45000028) + struct.pack('!L', 0) + struct.pack('!L', 0x40060000)
        tcp_rst += pkt[16:20] + pkt[12:16]   # swap addresses
        tcp_rst = tcp_rst[0:10] + struct.pack("!H", self.ip_checksum(tcp_rst)) + tcp_rst[12 :] # IP header
        #TCP header
        #Source and Dest  ports reversed
        tcp_rst += pkt[ihl+2:ihl+4] + pkt[ihl: ihl+2]
        #4 Bytes of seqno, #4 bytes of ackNo
 
        tcp_rst += struct.pack('!L', 0)
        tcp_rst += struct.pack('!L', (struct.unpack('!L', pkt[ihl + 4 : ihl + 8])[0] + 1)) 
 
        #.5 byte offset 1.5 bytes other stuff, 1 byte windowsize
 
 
        tcp_rst += struct.pack('!H', 0x5014) + struct.pack("!H",0) # flags and window
        tcp_rst = tcp_rst[0:36] + struct.pack('!H', self.tcp_checksum(tcp_rst)) + struct.pack("!H",0)
 
        return tcp_rst
 
    def tcp_checksum(self, pkt):
        checksum = 26
        for i in range(12, 36, 2):
            checksum += struct.unpack('!H', pkt[i: i+2])[0]
        checksum = (checksum >> 16) + checksum & 0xffff
        checksum = (checksum >> 16) + checksum & 0xffff
        return self.flip(checksum)
 
    def flip(self, num):
        flip = 0
        for i in range(0, 16):
            if not num & (1 << i):
                flip = flip | (1 << i)
        return flip
 
    def create_DNS_deny(self, pkt, domain):
        # Make a fake DNS packet and send it
        dns_pkt_ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4
 
        #Check if this packet is a DNS query. 1-bit QR field must be 0
        DNS_query = (ord(pkt[dns_pkt_ihl+10]) >> 3) & 15
 
        if DNS_query != 0:
            #Not a DNS query
            return
        # Create a new packet form IP header of old packet
        dns_pkt = pkt[:dns_pkt_ihl-8]
        dns_pkt += pkt[16:20] + pkt[12:16]
 
        # print dns_pkt
        # Swap direction of packet to deny
            # src_ip and dst_ip are swapped. src_port and dst_port are swapped
        rest_pkt = self.swap_pkt_dir(pkt[dns_pkt_ihl:]) 
        dns_pkt = dns_pkt + rest_pkt
 
        #reset TTL to 1?
        #dns_pkt = dns_pkt[:8] + struct.pack("!B", 1) + dns_pkt[9:]
        # UDP header, 8 more than original ihl
        #dns_pkt = dns_pkt + pkt[dns_pkt_ihl: dns_pkt_ihl + 4]
        # Empty UDP header
        dns_pkt += struct.pack('!L', 0)
 
        # Question Section
        # Row 1
        # Get DNS identifier from old packet
        dns_pkt = dns_pkt + pkt[dns_pkt_ihl+8:dns_pkt_ihl+10]
        # ROW 2
        # Set DNS response flags 0x8180 and copy RCODE over to the 0 error here
        dns_pkt = dns_pkt + struct.pack('!H',0x8000)
        # print len(dns_pkt)
 
        # ROWS 3-6 16 Bits each
        # DNS QDCOUNT = 1
        dns_pkt += struct.pack('!H',0x0001)
        # DNS ANCOUNT = 1
        dns_pkt += struct.pack('!H',0x0001)
        # DNS NSCOUNT = 0
        dns_pkt += struct.pack('!H',0x0000)
        # DNS ARCOUNT = 0
        dns_pkt += struct.pack('!H',0x0000)
 
        #print len(dns_pkt)
 
        # get domain name from query
        #dns_pkt = dns_pkt + pkt[dns_pkt_ihl+20:]
        i = dns_pkt_ihl + 20
        while ord(pkt[i]): i += 1
        dns_pkt += pkt[dns_pkt_ihl+20:i+1] + struct.pack('!L', 0x10001)
        # Get the domain name from query for Name
        dns_pkt += pkt[dns_pkt_ihl + 20 : i + 1] + struct.pack('!L', 0x10001) + struct.pack('!L', 1) + struct.pack('!H', 4) + socket.inet_aton("54.173.224.150")
 
        dns_pkt = dns_pkt[0:2] + struct.pack('!H', len(dns_pkt)) + dns_pkt[4:]
        dns_pkt = dns_pkt[0:10] + struct.pack("!H", self.ip_checksum(dns_pkt)) + dns_pkt[12 :]
        dns_pkt = dns_pkt [0:24] + struct.pack("!H", len(dns_pkt) - 20) +  dns_pkt[26:]
 
        return dns_pkt
 
    def swap_pkt_dir(self, pkt):
        #Swap src and dst ip
        src_ip = pkt[0:2]
        dest_ip = pkt[2:4]
        pkt = dest_ip + src_ip
        return pkt
    def ip_checksum(self, packet):
        retval = 0
        for i in range(0, 20, 2):
            if i!=10:
                retval += struct.unpack("!H", packet[i:i+2])[0]
 
        retval = retval//pow(2,16) + retval & 0xffff
        retval = retval//pow(2,16) + retval & 0xffff
        return self.complement(retval )
 
    def complement(self, num):
        retval = 0
        for i in range(16):
            retval |= ((num & 1)^1) << i
            num = num >> 1
        return retval
 
    def do_log_shit(self, address, pkt, direction, internal_port, seqno, syn, ack):
        key = (address, internal_port)
        if not self.http_logs.get(key):
            self.http_logs[key] = log_buffer(direction, address)
        if len(pkt)> 0:
            self.http_logs[key].parse_input(pkt, direction, seqno, syn, False)
        if self.http_logs[key].canPrint:
            f = open("http.log", "a")
 
            foo = (self.http_logs[key]).toString()
            if foo == False:
                print "Do not log. No rules apply"
            else:
                f.write(foo)
                f.write("\n")
                print "Check if things have been written."
            self.http_logs[key] = None
            f.flush()
 
class log_buffer:
    log_rules = []
    def __init__(self, direction, ip_address):
        self.incoming_seqno = None
        self.other_seqno = None
        self.pkt_direction = direction
        self.request_header = ""
        self.response_header = ""
        self.last_four_incoming = []
        self.last_four_outgoing = []
        self.ip_address = socket.inet_ntoa(struct.pack("!I", ip_address))
        self.stop_parsing_request = False
        self.stop_parsing_response = False
        self.canPrint = False


        self.first_response = False
 
    def parse_input(self, pkt, direction, seqno, syn, ack):
        #Request Packet
        if direction == PKT_DIR_OUTGOING:
            #Start the TCP HANDSHAKE. SynAck
            if self.incoming_seqno == None:
                #Setting seqNo to 0 relative
                self.incoming_seqno = seqno

            if self.incoming_seqno == seqno:
                if not syn:
                    self.last_four_incoming.append(pkt)
                    if not self.stop_parsing_request:
                        
                        if "\r\n\r\n" in pkt:
                            print "testing"
                            joe = pkt.split('\r\n\r\n')
                            pkt = joe[0]
                            print "Ending now"
                            self.stop_parsing_request = True

                        self.request_header += pkt
                if syn:
                    self.incoming_seqno += 1
                else:
                    if self.stop_parsing_request == False:
                        print "adding "
                        self.incoming_seqno += (len(pkt))
                self.incoming_seqno %= pow(2, 32)
            elif self.incoming_seqno < seqno:
                return

            elif self.incoming_seqno > seqno:
                pass

            else:
                return

        #Response Packet
        elif direction == PKT_DIR_INCOMING and self.stop_parsing_request:
            print " "
            print "###########################RESPONSE TIME!!!!!!"
            print pkt
            if self.other_seqno == None:
                print "First Response"
                self.other_seqno = seqno
                self.first_response = True

            if seqno == self.other_seqno:
                if not syn:
                    self.last_four_outgoing.append(pkt)
                    if len(self.last_four_outgoing) > 4:
                        self.last_four_outgoing.pop(0)
                    if not self.stop_parsing_response:
                        self.response_header += pkt
                if syn:
                    self.other_seqno += 1
                else:
                    print " This is not a SYN, RESPONSE packet"
                    
                    if "\r\n\r\n" in pkt:
                        print "found line break for response,  WE CAN WRITE NOW :D:D:D:D:D:D"
                        joe = pkt.split('\r\n\r\n')
                        pkt = joe[0]
                        print "Ending now :D:D:D:D:D:D :D:D:D:D:D:D :D:D:D:D:D:D:D:D:D:D:D:D"
                        self.canPrint = True
                        self.stop_parsing_request = True
                        self.first_response = False


                    self.request_header += pkt


                    if self.first_response == True:
                        print "First response"
                        self.other_seqno += max(1, (len(pkt)))
                        self.first_response = False

                    else: 
                        if self.stop_parsing_response == False:
                            self.other_seqno += (len(pkt))
                
                self.other_seqno = (self.other_seqno % pow(2,32))



            elif self.incoming_seqno < seqno:
                return

            elif self.incoming_seqno > seqno:
                #drop the packet
                pass

            else:
                return
 
    def http_create_log(self, http_request, http_response):
        # host_name method  path version status_code object_size
 
        # Match the packet to the rule[2] host to check if it works.
        # Split the http_response into a list by row.
        # Return values to be written will be log1, log2, log3, etc..
        host_name = None
 
        #these lines of code just strip off everything before the first HTTP method.
        super_hacky_regex = "(GET)|(POST)|(PUT)|(HEAD)|(POST)|(PUT)|(DELETE)|(TRACE)|(OPTIONS)|(CONNECT)|(PATCH)"
        hack = re.findall(super_hacky_regex, http_request)[0][0]
        first_match =  http_request.find(hack)
        http_request = http_request[first_match:]
 
        http_req_list = http_request.split('\n')
 
        for line in http_req_list:
            #Split each line by attribute and vlaue
            line_values = line.strip().split(':', 1)
            line_values = map(lambda x: x.strip(), line_values)
            if line_values[0].lower() == "host":
                host_name = line_values[1]
                break
 
        http_req_first_line = http_req_list[0].strip().split(" ")
        # Method field, usually a GET request
        method = http_req_first_line[0]
        # Path, usually /
        path = http_req_first_line[1]
        # Version
        version = http_req_first_line[2]
        # Status code, first line
 
        shave = http_response.index("HTTP")
        http_response = http_response[shave:]
        http_response = http_response.split("\r\n\r\n")[0]
        http_res_list = http_response.split('\n')
        http_res_first_line = http_res_list[0].strip().split(" ")
        status_code = http_res_first_line[1]
 
        object_size = -1
        for line in http_res_list:
            line_list = line.strip().split(":")
            line_list = map(lambda x:x.strip(), line_list )
            if line_list[0].lower() == "Content-Length".lower():
                object_size = int(line_list[1])
        http_log = False
        if host_name == None:
            http_log = " ".join([self.ip_address, str(method), str(path),  \
            str(version), str(status_code), str(object_size)])
        else:
            http_log = " ".join([host_name, str(method), str(path),  \
            str(version), str(status_code), str(object_size)])

        print "RETURNING HTTP LOG HERE"
        return http_log
 
    def checkDomain(self, domain):
        #Used to check if domain names match
        # print "Start"
        for i in self.log_rules:
            if domain:
                if "*" in i:
                    if i[0] != "*":
                        raise Exception("bad rule")
                    if i == "*":
                        return True
                    if i[1:] == domain[-len(i[1:]):]:
                        return True
                if i == domain:
                    return True
            if self.ip_address == i:
                return True
        return False
 
    def toString(self):
        return self.http_create_log(self.request_header, self.response_header)
