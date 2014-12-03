#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
import collections
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
# Authors: Allan Peng, Owen Chen
#hello
#swagmaster
class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # TODO: Load the firewall rules (from rule_filename) here.
        rules = open(config['rule'], "r")
 
        self.firewall_rules = []
        self.countryRules = {}
        self.countryCodes = set()
        self.log_rules = []
        #not sure what to do with this yet.
        self.http_logs = {}
        for rule in rules:
            #Get rid of all \n
            strip = rule.rstrip()
            #Parse each rule by word
            rule_list = strip.split(" ")
 
            #If first letter is a comment or empty rule
            if rule_list[0] == "%" or rule_list[0] == '':
                continue
 
            # log http
            if rule_list[0].lower() == "log" and rule_list[1].lower()== "http":
 
                self.log_rules.append(rule_list[2].lower())
 
            #Protocol/IP/Port Rule
            if rule_list[1].lower() != "dns":
 
                rule_format = [rule_list[0].upper(), rule_list[1].upper(), rule_list[2].upper(), rule_list[3].upper()]
            # DNS rule
            elif rule_list[1].lower() == "dns":
 
                rule_format = [rule_list[0].upper(), rule_list[1].upper(), rule_list[2].upper()]
 
            #If rule_List[2] is a country code, append it to self.countryCodes
            if len(rule_list[2]) ==2 and rule_list[2].isalpha():
                self.countryCodes.add(rule_list[2].upper())
            self.firewall_rules.append(rule_format)
 
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.
 
 
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
             #Convert IP into number
 
            start = struct.unpack("!I", socket.inet_aton(geo[0]))[0]
 
            end = struct.unpack("!I", socket.inet_aton(geo[1]))[0]
            country = geo[2].upper()
            if self.countryRules.get(country) == None:
                self.countryRules[country] = []
            ipRange = (start, end)
            self.countryRules[country].append(ipRange)
        #print("done bitch")
        #print self.countryRules.keys()
 
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        #print("handling packet")
        
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
 
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'
 
        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
 
 
        # TODO: Your main firewall code will be here.
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

        print (Transfer)
        #iterate through log rules here.
        if Transfer == "TCP":
            source_port, dest_port = self.parse_tcp(datagram)
            if pkt_dir == PKT_DIR_INCOMING:
                port = dest_port
                ext_addr = dest_address
                internal_port = source_port
            else:
                port = source_port
                ext_addr = source_address
                internal_port = dest_port
            if port == 80:
                offset = struct.unpack("!B",datagram[12]) [0]/16
                http_data = datagram[offset:]
                self.do_log_shit(ext_addr, http_data, pkt_dir, internal_port)
 
        if verdict:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
 
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
 
        if deny:
            if Transfer == "TCP" and pkt_dir == PKT_DIR_INCOMING:
                print ("TCP RST packet")
                source_port, dest_port = self.parse_tcp(datagram)
                rst_packet = self.create_tcp_packet(source_address, dest_address,\
                    source_port, dest_port)
                self.iface_ext.send_ip_packet(rst_packet)
            elif Transfer == "UDP":
                print ("DNS Deny")

                is_dns, domain = self.parse_dns(datagram)
                print is_dns
                print ("creating DNS_deny packet")
                print ("DNS deny method takes in the full original packet")
                dns_packet = self.create_DNS_deny(pkt, domain)
                print ("DNS PACKET CREATEDs")
                if pkt_dir == PKT_DIR_INCOMING:
                    print "incoming send outgoing"
                    self.iface_ext.send_ip_packet(dns_packet)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    print "outgoing sending ingoing"
                    self.iface_int.send_ip_packet(dns_packet)
                
            else:
                raise Exception
        else:
            print "Don't go here"
            pass
 
    #returns True if we pass on the packet. False if drop.
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
                        #print rule[0]
                        if rule[0] == "DROP":
                            verdict = False
                        if rule[0] == "DENY":
                            deny = True
                        if rule[0] == "PASS":
                            verdict = True
                            deny = False
 
            elif rule[1] == "DNS" and is_dns:
                #print("parsing dns")
        
                does_apply = False
                dns_domain_list = rule[2].lower()
                #print server
                #print dns_domain_list
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
                #print "does apply!"
                    if rule[0] == "DROP":
                        verdict = False
                    if rule[0] == "PASS":
                        verdict = True
                        deny = False
                    if rule[0] == "DENY":
                        deny = True                        
 
        if verdict == False:
            print "dropping packet"
        else:
            print"passing"
 
        return (verdict, deny)
 
    def applicable_rule(self, rule, dest_address, port):
        #Used to see if we should apply the verdict
        #Is packet protocol == rule[1]?
        result = self.valid_ip(rule, dest_address) and self.valid_port(rule, port)
        return result
 
    def in_range(self, a, inRange):
        return a <= inRange[1] and a >= inRange[0]
 
    #returns True if IP_address belongs to country.
    def in_country(self,a, country):
        #binary search
        #print a
 
        #print country
        country = self.countryRules[country]
        minimum = 0
        maximum = len(country)
        while minimum < maximum:
            i = (minimum + maximum)/2
 
            if self.in_range(a, country[i]):
                #print "TRUE"
                return True
 
            if country[i][0] >  a:
                maximum = i -1
            elif country[i][0] < a:
                minimum = i +1
 
        #print "FALSE FALSE FALSE"
        return False
    #Rule list, IP Address
    def valid_ip(self, rule, address):
        #don't forget drop.
        #Any
        #print rule[2]
        if rule[2] == "ANY":
            #print "ANANYANDA"
            return True
        #2 byte country code
        if len(rule[2]) == 2:
            #print "country code"
            #print rule[2]
        
 
            #print "country!!!!"
            return self.in_country(address, rule[2])
 
        #IP prefix
        elif "/" in rule[2]:
            #Split the slash notation
            #Range = 2 ^ (32 - Number after slash notation) IP addresses in range.
            #IP number be32 - fore slash converted to
            #If rule[2] converted to a number is bigger than lower bound and lower than upper bound
            #Return True.
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
 
    #DNS Cases
    # TODO: You can add more methods as you want.
    #parses ip header
    #returns a tuple containing:
    #(Protocol, bytes_in_packet, source, destination)
    #Protocol is NONE if not TCP,UDP, or ICMP
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
        #print "THIS IS A DNS PACKET"
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
        #Protocol = TCP or something
        #TCP = 6
        #UDP = 17
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
    def create_tcp_packet(self, source_addr, dest_addr, source_port, dest_port):
 
        offset = 5
        hw1 = source_port
        hw2 = dest_port
 
        flags = int("000010100", 2)
        tcp_data = ""
        hw3 = 0
        hw4 = 1
        hw5 = 0
        hw6 = 1
        hw7 = (offset << 12)|flags
        #the fuck's a window?
        hw8 = 0
        #hw9 = checksum
        #urgent pointer
        hw10 = 0
 
        retval = self.create_ip_header("TCP", source_addr, dest_addr)
        retval += struct.pack("!HHHHHHHH", hw1, hw2, hw3, hw4, hw5, hw6, hw7, hw8)
        retval += self.tcp_checksum(source_addr, dest_addr, (list(hw1, hw2, hw3, hw4, hw5, hw6, hw7, hw8, hw10)))
        retval += struct.pack("!H", hw10)
        return retval
 
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

        print dns_pkt
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
        #dns_pkt = dns_pkt + "\x81" + (chr(struct.unpack('!B', "\x80")[0] | ord(pkt[dns_pkt_ihl+11])))
        dns_pkt = dns_pkt + struct.pack('!H',0x8000)
        print len(dns_pkt)

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
        dns_pkt = dns_pkt[0:10] + struct.pack("!H", self.ip_checksum(dns_pkt)) + dns_pkt[12 :] #
        dns_pkt = dns_pkt [0:24] + struct.pack("!H", len(dns_pkt) - 20) +  dns_pkt[26:] 
        # # Response type A
        # dns_pkt += struct.pack('!H',0x0001)
 
        # # Response class to class INCOMING
        # dns_pkt += struct.pack('!H',0x0001)
 
        # #DNS answer section 

        # # DNS query TTL to 1 second

        # dns_pkt += struct.pack('L', 0x00000001)


        # # datalength is 4 octects for IPv4
        # dns_pkt += struct.pack('!H',0x0004)
        
 
        # # add the spoofed IP to DNS response.
        # dns_spoof_ip = '54.173.224.150'
        # dns_spoof_ip = socket.inet_aton(dns_spoof_ip)
    
        # dns_pkt = dns_pkt + dns_spoof_ip
        


        # dns_split = dns_spoof_ip.split('.')
        # converted_ip = []
        # for k in dns_split:

        #     converted_ip.append(struct.pack("!H", k))
        # dns_pkt += str.join('', converted_ip)
 
        # update UDP header size
        # dns_pkt = dns_pkt[:dns_pkt_ihl+4] + struct.pack('!H', len(dns_pkt) - dns_pkt_ihl) + dns_pkt[dns_pkt_ihl+6:]
 
        # Add udp checksum and ip checksum

        # dns_pkt = add_udp_checksum
        # dns_pkt = self.ip_checksum()
 
        # Send denied DNS response to host behind the firewall

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
 

 
    #returns a string.
    #source_address: 32 bits
    #tcp_length: Compute on the fly. len(tcp)data + 20
    #tcp_header: a list of each 16-bit word in the header except chcekcsum
    #tcp_data. Yeah.
    def tcp_checksum(self, source_address, dest_address, tcp_header, tcp_data):
        solution = []
        solution.append(source_address & 0xffff)
        solution.append(source_address//0xffff)
        solution.append(dest_address & 0xffff)
        solution.append(dest_address//0xffff)
        solution.append((len(tcp_data) + len(tcp_header) + 2))
        solution += tcp_header
        i = 0
        while i < len(tcp_data):
            if i+1 == len(tcp_data):
                solution.append(tcp_data[i] + "\x00")
            else:
                solution.append(tcp_data[i, i+2])
            i += 2
        return self.ip_checksum(solution)
 
    def udp_checksum(self, *args):
        #too lazy to implement
        return "\xff\xff"
 
    def do_log_shit(self, address, pkt, direction, internal_port):
        key = (address, internal_port)
        if self.http_logs.get(key) == None:
            self.http_logs[key] = log_buffer(direction, address)
 
        #get seqNo somehow. 
        self.http_logs[key].parse_input(pkt, direction, seqNo)
        if self.http_logs[key].canPrint:
            f = open("http.log", "a")
            f.write(self.http_logs[key])
            self.http_logs[key] = None
            f.flush()
 
 
class log_buffer:
    def __init__(self, direction, ip_address):
        self.nextSeqNo = 0
        self.incoming_direction = direction
        self.text = ""
        self.request_header = ""
        self.response_header = ""
        self.last_four_packets = []
        self.ip_address = ip_address
        self.stage = 0
        self.writing_response_body = False
        self.canPrint = False
        self.writing_response = False
 
    def parse_input(self, pkt, direction, seqNo):
        #still parsing request
 
        if seqNo == self.seqNo:
 
            self.last_four_packets.append(pkt)
            self.text += pkt
 
            if len(self.last_four_packets) >4:
                self.last_four_packets.pop(0)
 
            # constructing request body ---> PROBABLY ONLY POST REQUEST
            # do nothing in this case.
            if self.stage == 1 and direction == self.incoming_direction:
                pass
 
            #response_header
            # we're getting the response header now.
            if self.stage == 1 and direction != self.incoming_direction:
                self.writing_response = True
 
            #should be done by now.
            #we're writing the response body.
            if self.stage == 2 and self.writing_response:
                self.writing_response_body = True
 
            # we're writing the response
            if self.stage == 3 and self.writing_response:
                self.writing_response_body = True
 
            if "\r\n\r\n" in "".join(self.last_four_packets):
                if self.stage == 0:
                    self.request_header = self.text
                    self.text = ""
                if self.stage == 1:
                    if self.writing_response:
                        self.response_header = self.text
                        self.text = ""
                if self.writing_response_body:
                    self.canPrint = True
                self.stage += 1
                self.last_four_packets = []
        else:
            pass
 
 
    def http_create_log(self, http_request, http_response, ext_ip):
        # host_name method  path version status_code object_size
 
        # Match the packet to the rule[2] host to check if it works.
        # Split the http_response into a list by row.
        # Return values to be written will be log1, log2, log3, etc..
        host_name = None
        http_req_list = http_request.split('\n')
 
        for line in http_req_list:
            #Split each line by attribute and vlaue
            line_values = line.split(':')
            if line_values[0].lower() == "host":
                host_name = line_values[1]
                break
        #if host_name is false, use external IP
 
        http_req_first_line = http_req_list[0].split(" ")
        #Method field, usually a GET request
        method = http_req_first_line[0]
        #Path, usually /
        path = http_req_first_line[1]
        # Version
        version = http_req_first_line[2]
        #Status code, first line
        http_res_list = http_response.split('\n')
        http_res_first_line = http_res_list[0].split(" ")
        status_code = http_res_first_line[1]
 
        #if not present, -1
        object_size = -1
        for line in http_res_list:
            line_list = line.split(":")
            if line_list[0].lower() == "Content-Length".lower():
                object_size = int(line_list[1])
 
        http_log = [str(method), str(path), str(version), str(status_code), str(object_size)].join(" ")
 
        if self.checkDomain(host_name, ext_ip):
            f.writelines(http_log)
            f.flush()
        return
 
 
    def checkDomain(self, domain, ip_address):
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
                    return i == domain
            if socket.inet_aton(ip_address) == i:
                return True
        return False
 
    def __repr__(self):
        return self.http_create_log(self.request_header, self.response_header, self.ip_address)
