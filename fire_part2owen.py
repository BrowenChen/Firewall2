#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
# Authors: Allan Peng, Owen Chen



# TODO MISSING: 
    # 1) Make seperate http_buffers for incoming and outgoing. Keep seqno and header information
    # 2) HTTP log writes, take into account 
                # 1) no host, using ext_ip
                # 2) dotted quad
                # 3) normal domain name

    # 3) flow of requests and sends. Persistent conncetions
    # 4) Drop and Pass packets
    # 5) If after '/r/n/r/n' for first request, does response come immediately after?


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # TODO: Load the firewall rules (from rule_filename) here.
        

        self.firewall_rules = []
        self.countryRules = {}
        self.countryCodes = set()


        # self.log_rules = []


        # -----For http logging----------
        
        #self.prev_http_type
        #self.http_buffer = {} [key is [ip_src, ip_dst, port_src, port_dst], value is [pkt_request info, pkt_response info]]
        #self.prev_http_type = "" This is the last HTTP type we sent out, request or response. After a response, we can log packet
        #self.next_seq_no

        

        #incoming_http_buffer each has: seqno, has_header, expected seqno, ..
        #outgoing_http_buffer

        # -----For http logging----------


        rules = open(config['rule'], "r")

        #iterate through rules
        # for rule in rules:
            #Get rid of all \n
            # strip = rule.rstrip()

            #Parse each rule by word
            # rule_list = strip.split(" ")

            #If first letter is a comment or empty rule

            # if rule_list[0] == "%" or rule_list[0] == '':
            #     continue

            #If len(rule) > 2, then it is a rule:

                # if rule_list[1].lower() != "dns":

                #     rule_format = [rule_list[0].lower, rule_list[1].lower(), rule_list[2].lower(), rule_list[3].lower()]
                
                # elif rule_list[1].lower() == "dns":
                #     rule_format = [rule_list[0].lower(), rule_list[1].lower(), rule_list[2].lower()]
                
                # elif rule_list[0].lower() == "log" and rule_list[1] == "http":
                    #rule_format is ["log", "http", rule_list[2].lower()]

            #If rule_List[2] is a country code, append it to self.countryCodes
            # if len(rule_list[2]) ==2 and rule_list[2].isalpha():
            #     self.countryCodes.add(rule_list[2].upper())
            
            # Add to firewall_rules
            # self.firewall_rules.append(rule_format) 

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.

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
            country = geo[2].lower()
            if self.countryRules.get(country) == None:
                self.countryRules[country] = []
            ipRange = (start, end)
            self.countryRules[country].append(ipRange)

        # TODO: Also do some initialization if needed.
        # Initialize self.log = open('http.log', 'a')

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):

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

        # Make packet Object, packet_object, to parse attributes
        # pkt_object = firewall_pkt(pkt). This will have all the packet attributes in a class

        
        # ---------------Iterate through log rules------------------------------

        # ------NOTES------------
        # If seqno is less than next seqNo, pass packet. Else drop if senqno != nextSeqno

        # ------NOTES------------
        
        # Iterate the packet through the list of http log rules here
        # f = open("http.log", "a")
        #self.log_rules = log_rules

        # for rule in log_rules
            # if rule[0] is "log" and rule[1] is "http"
                #has to be tcp and port 80. pkt_object.protocol_name and pkt_object.port
                    
                    #get the tcp_header_size
                    #http_offset = ihl + tcp header size
                    #get the http content by using the http_offset value. 
                    
                    #get the packet_list
                    #get the http string.

                    #If packet is INCOMING: 
                        
                        #Get sequence flag from TCP header, 1 bit
                        #get sequence number from TCP header, 4 bytes long. This is how many bytes have been received 
                        #make a key of packet's initial ip, destination ip, initial port, destination port
                            #Parse IP and TCP headers. Get the http payload of the packet


                        #if seqNo < next_seq_response:
                            #pass the packet 

                        #if seqNo > next_seq_response: 
                            #Drop the packet

                    # TODO: ****************************************

                    #     if last_http_type is 'request':
                    #         
                    #         if next_seq_response = sequence, then this is okay to go
                    #             if key is in the http_buffer
                                    
                                    #add the key into the http_buffer. Value is the payload
                                        #if the value of this payload is '\r\n\r\n', then there is a break after HTTP header. 
                                            #last_http_type is now 'response'. This is the first message break. 

                                    #update the next_seq_response += len(this packet's payload)

                            # else drop the packet because out of order

                    #     elif last_http_type is 'response': we are sending out a request after getting a response
                            #if next_seq_response = sequence:
                                # if key is in http_buffer:

                                    #WHAT TO DO HERE ----------------------------------------

                                    #update the next_seq_response += len(this packet's payload)
                                    #if this packet's payload is '\r\n\r\n', then this is the response break. Start HTTP content body 

                    #     elif sequence_flag is FIN or SYN
                    #         next_seq_response is seq+1 b/c it only increase by one 

                    # TODO: not finished here ****************************************

                    # elif packet is OUTGOING
                        #We log outgoing HTTP packets. 

                        #Get sequence flag
                        #Get seuqnce number
                        #Get the key [initialIP, outgoingIP, intialPort, outgoingPort]

                        #if packet payload > 0 
                            #handle request and response
                            #if last_http_type = response

                                #if this key is in the http_buffer, 


                                    # If content is '\r\n\r\n'   #we can LOG now
                                        #Get request info 
                                        #Get response info
                                        #http_create_log() function
                                    # else:
                                        #http_buffer[key][1] += pkt[http_offset:]

                                #self.next_seq_request += len(pkt[http_offset:]), update next seq Number        


                            #if last_http_type = request
                                # We are sending out a response
                                #if key is in self.http_buffer:
                                    #http_buffer[key][0] += pkt[http_offset:]
                                    
                                #Else, create a new request for (key) in http buffer
                                    #self.http_buffer[key] = [pkt[http_offset:]]
                                
                                #self.next_seq_request += len(pkt[http_offset:]), update next seq Number


                        #If seq_flag is 2, sending SYN pkt
                            #update next_seq_request by 1
                            #update last_http type as a request

                        #If seq_flag is 1, this is a FIN
                            #clear buffer


        # ---------------Iterate through log rules------------------------------




        #Go through firewall rules
            #If not DNS rule, might be TCP deny
                # Check if the verdict applies. Verdict could be drop pass or deny
                
                    #if rule[0] == "deny":
                        #call the send_rst method

                        # TODO: not finished here ****************************************
                        #TCP_RST_PACKET()

            #If packet is a DNS rule
                #If the packet is not DNS
                    #Cntinue
                #Check dns rule to see if verdict applies

                    #If rule[0] == "deny":
                        #DNS deny 
                        #If packet_object is_AAAA:
                            #Drop return
                        #Else send DNS deny packet with blocked address to DNS initiator (src addrs, src port)
                        
                            # TODO: not finished here ****************************************
                            # DNS_DENY () 

        #None of the rules matched

    def http_create_log(self, http_request, http_response, log_rule, ext_ip):
        # host_name   method  path    version status_code object_size
        # 
        # Match the packet to the rule[2] host to check if it works. 
        # Split the http_response into a list by row. 
        # Return values to be written will be log1, log2, log3, etc..
        host_present = False 
        http_req_list = http_request.split('\r\n')

        for line in http_req_list:
            #Split each line by attribute and vlaue
            line_values = line.split(':')
            if line_values[0].lower() == "Host".lower():
                
                host_name = line_values[1]
                host_present = True

        if host_present == False:
            #log1 is the ext_ip of the TCP connection 
            # host_name = struct.pact(external_ip) #PARSE this

        http_req_first_line = http_req_list[0].split(" ")
        #Method field, usually a GET request
        method = http_req_first_line[0]
        #Path, usually /
        path = http_req_first_line[1]
        # Version 
        version = http_req_first_line[2]

        #Status code, first line
        http_res_list = http_response.split('\r\n')

        http_res_first_line = http_res_list.split(" ")
        status_code = http_res_first_line[2]

        #if not present, -1
        object_size = -1
        for line in http_res_list:
            line_list = line.split(":")
            if line_list[0].lower() == "Content-Length".lower():
                object_size = int(line_list[1])


        http_log = str(method) + " " + str(path) + " " + str(version) + " " + str(status_code) + " " + str(object_size) 



        #TO BE CONTINUED
        log_verdict = False
        if host_present == True:
            dns_domain = rule[2][::-1]
            log_verdict = self.check_domain(dns_domain, host_name)

        #if log_verdict == True:
            #Log http_log

        #FIGURE OUT HOW TO LOG ONLY ONCE AND NOT LOG MULTIPLE TIMES IF MULTIPLE RULES MATCH
        if log_verdict:
            f.writelines(http_log)
            f.flush()

        return


    def checkDomain(self, domain, checkDomain):
        #Used to check if domain names match
        # print "Start"
        dns_domain = domain.split(".")
        check_domain = checkDomain.split(".")

        if "*" in dns_domain:
            if dns_domain[0] != "*":
                print "malformed"
                return False
            # print "Yes"
            dns_domain_rest = dns_domain[1:]
            splice = len(check_domain) - len(dns_domain_rest)
            dns_check_rest = check_domain[splice:]
            # print dns_domain_rest
            return (dns_check_rest == dns_domain_rest)
        else:
            return (dns_domain == check_domain)

    def create_TCP_rst(self):

        # add udp checksum
        # add ip checksum
        pass

    def create_DNS_deny(self, pkt):
        # Make a fake DNS packet and send it

        dns_pkt_ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4
        #Check if this packet is a DNS query. 1-bit QR field must be 0
        DNS_query = ord(pkt[dns_pkt_ihl+10] >> 3) & 15
        if DNS_query != 0:
            #Not a DNS query
            return 
        
        
        
        # Create a new packet form IP header of old packet
        dns_pkt = pkt[:dns_pkt_ihl]

        #reset TTL to max value
        dns_pkt = dns_pkt[:8] + struct.pack("!B", 255) + dns_pkt[9:]
    
        
        # UDP header, 8 more than original ihl
        dns_pkt = dns_pkt + pkt[dns_pkt_ihl: dns_pkt_ihl + 8]
        
        # Swap direction of packet to deny
            # src_ip and dst_ip are swapped. src_port and dst_port are swapped
        dns_pkt = self.swap_pkt_dir(dns_pkt)
        
        # Row 1
        # Get DNS identifier from old packet
        dns_pkt = dns_pkt + pkt[dns_pkt_ihl+8:dns_pkt_ihl+10]

    
        # ROW 2
        # Set DNS response flags 0x8180 and copy RCODE over to the 0
        dns_pkt = dns_pkt + "\x81" + (chr(ord("\80") | ord(pkt[dns_pkt_ihl+11])))
        
        # ROWS 3-6 16 Bits each
        # DNS QDCOUNT = 1
        dns_pkt += "\x00\x01"
        # DNS ANCOUNT = 0?
        dns_pkt += "\x00\x01"
        # DNS NSCOUNT = 0
        dns_pkt += "\x00\x00"
        # DNS ARCOUNT = 0
        dns_pkt += "\x00\x00"
        
        # get domain name from query
        dns_pkt = dns_pkt + pkt[dns_pkt_ihl+20:]

        # Get the domain name from query for Name
        #Confused here, this is the value to set pointer to query domain?
        dns_pkt += "\c0\0c"


        # Response type A
        dns_pkt += "\x00\x01"

        # Response class to class INCOMING
        dns_pkt += "\x00\x01"
        
        # DNS query TTL to 1 second
        dns_pkt += "\x00\x00\x00\x01"
        # datalength is 4 octects for IPv4
        dns_pkt += "\x00\x04"

        # add the spoofed IP to DNS response.
        dns_spoof_ip = '54.173.224.150'

        # hstruct.pack("!I", socket.inet_aton(dns_spoof_ip))[0]

        dns_split = dns_spoof_ip.split('.')
        converted_ip = []
        for k in dns_split:
            converted_ip.append(struct.pack("!H", k))
        dns_pkt += str.join('', converted_ip)

        # update UDP header size
        dns_pkt = dns_pkt[:dns_pkt_ihl+4] + struct.pack('!H', len(dns_pkt) - dns_pkt_ihl) + dns_pkt[dns_pkt_ihl+6:]

        # Add udp checksum and ip checksum
        # dns_pkt = add_udp_checksum
        # dns_pkt = add_ip_checksum

        # Send denied DNS response to host behind the firewall
        self.iface_int_send_ip_packet(dns_pkt)
        return

    def tcp_checksum(self):
        pass

    def ip_checksum(self):
        pass

    def udp_checksum(self):
        pass

    # # takes in an unspecified amount of 16-bitstrings
    # #and returns their checksum.
    # def ip_checksum(self, *args):
    #     total = reduce(lambda x, y: x + y, args)
    #     while len(bin(total)) > (16 + 2):
    #         total = total & 0xffff + total //0xffff
    #     return self.flip(total)
 
    # # because ~ doesn't fucking do what it's fucking
    # # supposed to do.
    # def flip(self, foo):
    #     solution = ""
    #     for i in range(16):
    #         solution = str(1^(1&foo)) + solution
    #         foo>>=1
    #     return solution



    def swap_pkt_dir(self, pkt):
        #Swap src and dst ip
        src_ip = pkt[12:16]
        dest_ip = pkt[16:20]
        pkt = pkt[:12] + dest_ip + src_ip + pkt[20:]
        #swap ports
        # ------TODO------
        # dns_ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4

        # srcport = pkt[ihl:ihl+2]
        # destPort = pkt[ihl+2:ihl+4]

        # pkt = pkt[:ihl] + destPort + srcport + pkt[ihl+4:]

        return pkt
        

    def packet_quality(self):
        #If IHL of packet is less than 20, bad packet

        pass

    class Firewall_Pkt:
        def __init__(self, pkt_dir, pkt):
            #Set packet attributes
            
            #Set packet directions

            
            #Set Packet Protocol
                #Self.protocol = struct.unpack pkt[9:10]
                #If protocol == 1, self.protocol_name = icmp
                #Elif protocoll == 6: self.protocol_name = tcp
                #Elif protocol == 17: self.protocol_name = udp
                #Else: something else


            #Set Packet IP
                #if self.pkt_dir == PKT_DIR_INCOMING
                    #self.ip = 12:16
                # if self.pkt_dir == PKT_DIR_OUTGOING
                #     self.ip = 16:20


            #Set packet IP Header size
                # self.ihl = unpack the ip header size
                # self.ihl = (ord(struct.unpack('!s', pkt[0])[0]) & 15) * 4

            #Set Port 
                # self.port
                # If self.protocol == 1
                    # ICMP, get icmpt type.
                # if self.protocol == 6:
                #     This is a TCP port
                #     If pkt_dir is PKT_DIR_INCOMING
                #         self.port = packet IHL: packetIHL+2
                #     if pkt_dir is outgoing
                #         self.port is the next two bytes after ^^^
                # If protocol is 17
                #     UDP Same as TCP i think

                # self.initial_port unpack ihl: ihl+2
                # self.destination_port unpack next two bytes after the initial



            #Get packet UDP header size if UDP
                #if self.protocol is UDP/17, self.upd_size is ihl+4:ihl+6
            
            #Check if packet is DNS
                #is_dns and is_AAAA initially false
                #If packet isnt UDP, 53, outbound
                    #Check DNS QDCOUNT
                        #Check DNS QTYPE to 1 or 28
                            # DNS packet must be QCLASS of 1
                                # Self is_dns and is_AAAA to be true



            #If packet is DNS, get the domain list
                # self.domain = ""
                # self.domain_list
                # If self.is_dns
                #     get the dns_packet_domain

            #Check packet quality
                #if ihl is less than 20, bad_packet == true
                #p


            pass
        pass

