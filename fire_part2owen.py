#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
# Authors: Allan Peng, Owen Chen

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # TODO: Load the firewall rules (from rule_filename) here.
        

        self.firewall_rules = []
        self.countryRules = {}
        self.countryCodes = set()


        # self.log_rules = []

        #self.prev_http_type


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
        
        # Iterate the packet through the list of http log rules here
        # log_rules = open("http.log", "a")

        # for rule in log_rules
            # if rule[0] is "log" and rule[1] is "http"
                #has to be tcp and port 80. pkt_object.protocol_name and pkt_object.port
                    #get the tcp_header_size

                    #Get the http offset
                    #get the http content
                    #get the packet_list
                    #get the http string

                    #If packet is INCOMING
                        #Get sequence flag
                        #get sequence
                        #make a key of packet's initial ip, destination ip, initial port, destination port

                    # TODO: not finished here ****************************************


                    #     if last_http_type is 'request':
                    #         last_http_type is now 'response'
                    #         if next_seq_response = sequence
                    #             if key is in the http_buffer
                        

                    #     elif last_http_type is 'response':
                    #         if key is in http_buffer:

                    #     elif sequence_flag is 18:
                    #         next_seq_response is seq+1


                    # elif packet is outgoing



        # ---------------Iterate through log rules------------------------------


        #Test packet Quality. Return if bad
        #if packet_object.pkt_quality == False:
            #return

        #TODO: If the rule is a log http <rule> we check pkt. If match, log it
        #Iterate packet through list of reversed rules
        #For rule in self.log_rules:
            #Check if the rule is a log and http Rule
            #if rule[0] == "log" and rule[1] == "http":
                
                #Check if the packet is TCP and external port 80
                #If packet_object.protocol_name == "tcp" and packet_object.extPort == 80:

                    #Check if request or response pkt

                #Else 


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


    def create_TCP_rst(self):

        # add udp checksum
        # add ip checksum
        pass

    def create_DNS_deny(self):
        # Make a fake DNS packet and send it

        # Check if DNS query


        # Create a new packet form IP header of old packet
        # UDP header
        # TTL to max
        # Swap direction of packet to deny
        # Get DNS identifier
        # Set DNS response flags and copy RCODe
        # DNS QDCOUNT
        # DNS ANCOUNT
        # DNS NSCOUNT
        # DNS ARCOUNT
        # get domain name from query
        # Add pointer to sstart of queried name
        # Response type A
        # Response class to class INCOMING
        # DNS query TTL to 1 second
        # Define address block as 4 octects
        # add the spoofed IP to DNS response
        # UDP header size
        # Add udp checksum and ip checksum

        # Send denied DNS response to host behind the firewall

        pass

    def tcp_checksum(self):
        pass

    def ip_checksum(self):
        pass

    def udp_checksum(self):
        pass

    def packet_quality(self):
        pass

    def create_firewall_packet():
        # Create a firewall packet
        # Include protocol_type
        # ExtPort
        # 
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

