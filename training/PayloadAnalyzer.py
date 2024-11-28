import pandas as pd
import numpy as np
from scapy.all import rdpcap
from scipy.spatial.distance import mahalanobis
from scipy.linalg import inv
import matplotlib.pyplot as plt
from scipy.stats import chisquare
from scapy.all import *
#%%
sbytes = 'sbytes'
dbytes = 'dbytes'
dur = 'dur'
proto = 'proto'
sttl = 'sttl'
dttl = 'dttl'
sloss = 'sloss'
dloss = 'dloss'
Spkts = 'Spkts'
Dpkts = 'Dpkts'

#%%
# Load the tcpdump file
packets = rdpcap('/home/grauzone/projects/bakalarka/code/datasets/inside.tcpdump')  # File extension doesn't matter
flows = {}
def parse_to_flows(packet):
    global flows
    flow_id = (packet['IP'].src, packet['IP'].dst, packet['TCP'].sport, packet['TCP'].dport)
    if flow_id not in flows:
        flows[flow_id] = []
    flows[flow_id].append(packet)
    
for packet in packets:
    if 'IP' in packet and 'TCP' in packet:
        parse_to_flows(packet)
    
#%%
class PacketInfo:
    TYPE_IP = "IP"  # Internet Protocol (IPv4)
    TYPE_ARP = "ARP"  # Address Resolution Protocol
    TYPE_IPv6 = "IPv6"  # Internet Protocol (IPv6)
    TYPE_IPX = "IPX"  # Internetwork Packet Exchange
    TYPE_VLAN = "VLAN"  # IEEE 802.1Q (VLAN tagging)
    TYPE_PPP = "PPP"  # Point-to-Point Protocol
    TYPE_MPLS = "MPLS"  # Multiprotocol Label Switching
    TYPE_MPLS = "MPLS"  # MPLS with downstream-assigned label
    TYPE_PPPoE = "PPPoE"  # PPP over Ethernet (Discovery stage)
    TYPE_PPPoE = "PPPoE"  # PPP over Ethernet (Session stage)
    TYPE_QinQ = "QinQ"  # 802.1ad (Q-in-Q VLAN tagging)
    TYPE_Realtek = "Realtek"  # Realtek protocol
    TYPE_LLDP = "LLDP"  # Link Layer Discovery Protocol
    TYPE_FCoE = "FCoE"  # Fibre Channel over Ethernet
    TYPE_FCoE = "FCoE"  # FCoE Initialization Protocol

    # Define packet types (Ethertypes)
    TYPES = {
        0x0800: TYPE_IP,  # Internet Protocol (IPv4)
        0x0806: TYPE_ARP,  # Address Resolution Protocol
        0x86DD: TYPE_IPv6,  # Internet Protocol (IPv6)
        0x8137: TYPE_IPX,  # Internetwork Packet Exchange
        0x8100: TYPE_VLAN,  # IEEE 802.1Q (VLAN tagging)
        0x880B: TYPE_PPP,  # Point-to-Point Protocol
        0x8847: TYPE_MPLS,  # Multiprotocol Label Switching
        0x8848: TYPE_MPLS,  # MPLS with downstream-assigned label
        0x8863: TYPE_PPPoE,  # PPP over Ethernet (Discovery stage)
        0x8864: TYPE_PPPoE,  # PPP over Ethernet (Session stage)
        0x88A8: TYPE_QinQ,  # 802.1ad (Q-in-Q VLAN tagging)
        0x8899: TYPE_Realtek,  # Realtek protocol
        0x88CC: TYPE_LLDP,  # Link Layer Discovery Protocol
        0x8906: TYPE_FCoE,  # Fibre Channel over Ethernet
        0x8914: TYPE_FCoE,  # FCoE Initialization Protocol
    }

    PROTOCOL_ICMP = "ICMP"  # Internet Control Message Proto
    PROTOCOL_IGMP = "IGMP"  # Internet Group Management Prot
    PROTOCOL_TCP = "TCP"  # Transmission Control Protocol
    PROTOCOL_UDP = "UDP"  # User Datagram Protocol
    PROTOCOL_IPv6 = "IPv6"  # IPv6 encapsulation
    PROTOCOL_GRE = "GRE"  # Generic Routing Encapsulation
    PROTOCOL_ESP = "ESP"  # Encapsulating Security Payload
    PROTOCOL_AH = "AH"  # Authentication Header
    PROTOCOL_ICMPv6 = "ICMPv6"  # Internet Control Message Pr
    PROTOCOL_OSPF = "OSPF"  # Open Shortest Path First
    PROTOCOL_SCTP = "SCTP"  # Stream Control Transmission
    PROTOCOL_MPLS = "MPLS"  # MPLS-in-IP
    PROTOCOL_FCoE = "FCoE"  # Fibre Channel over Ethernet

    # Define IP-based protocols
    PROTOCOLS = {
        1: PROTOCOL_ICMP,  # Internet Control Message Protocol
        2: PROTOCOL_IGMP,  # Internet Group Management Protocol
        6: PROTOCOL_TCP,  # Transmission Control Protocol
        17: PROTOCOL_UDP,  # User Datagram Protocol
        41: PROTOCOL_IPv6,  # IPv6 encapsulation
        47: PROTOCOL_GRE,  # Generic Routing Encapsulation
        50: PROTOCOL_ESP,  # Encapsulating Security Payload
        51: PROTOCOL_AH,  # Authentication Header
        58: PROTOCOL_ICMPv6,  # Internet Control Message Protocol for IPv6
        89: PROTOCOL_OSPF,  # Open Shortest Path First
        132: PROTOCOL_SCTP,  # Stream Control Transmission Protocol
        137: PROTOCOL_MPLS,  # MPLS-in-IP
        138: PROTOCOL_FCoE,  # Fibre Channel over Ethernet
    }

    @classmethod
    def get_packet_type(cls, eth_type):
        if eth_type in cls.TYPES:
            return cls.TYPES[eth_type]
        else:
            return f'{hex(eth_type)}'

    @classmethod
    def get_packet_protocol(cls, protocol):
        if protocol in cls.PROTOCOLS:
            return cls.PROTOCOLS[protocol]
        else:
            return f'{protocol}'
#%%

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1
flow_lengths = [len(flow) for flow in flows.values()]
print(max(flow_lengths))
flow = list(flows.values())[0]
flow_data = {}
times = [float(pkt.time) for pkt in flow]
flow_data['dur'] = max(times) - min (times)
for packet in flow:
    flow_data['proto'] = packet['IP'].proto
    print(packet.summary())
    # for layer in get_packet_layers(packet):
    #     print (layer.name)
    
#%%
import logging
from Helper import Log

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.all import *
from PacketInfo import PacketInfo


class PacketParameter:

    def __init__(self, ether_pkt, pkt_time):

        # get ether packet info
        self.src_mac = ether_pkt.src
        self.dst_mac = ether_pkt.dst
        self.time_stamp = pkt_time

        self.type = PacketInfo.get_packet_type(ether_pkt.type)
        self.length = len(ether_pkt)

        self.type_protocol_name = self.type
        self.protocol_length = self.length - 14
        print(self.type)
        # print(ether_pkt.proto)

        if self.type == PacketInfo.TYPE_ARP:  # process ARP messages
            self.protocol_length -= 18  # 18 is padding size for ARP messages
            self.payload = 0

        elif self.type == PacketInfo.TYPE_Realtek:  # process Realtek Messages
            self.payload = 0  # actually the payload is unknown

        elif self.is_ip_based():
            print("Is ip based")
            ip_pkt = ether_pkt[IP] if self.type == PacketInfo.TYPE_IP else ether_pkt[IPv6]
            self.protocol_length -= (ip_pkt.ihl * 4 if self.type == PacketInfo.TYPE_IP else 40)

            if self.type == PacketInfo.TYPE_IP:
                proto = ip_pkt.proto
            else:
                if not ip_pkt.nh ==0:
                    proto = ip_pkt.nh
                else:
                    if IPv6ExtHdrHopByHop in ip_pkt:
                        hop_by_hop_header = ip_pkt[IPv6ExtHdrHopByHop]
                        proto = hop_by_hop_header.nh
                    else:
                        proto = 0

            self.protocol = PacketInfo.get_packet_protocol(proto)
            self.type_protocol_name += ':' + self.protocol

            self.ttl = ip_pkt.ttl if self.type == PacketInfo.TYPE_IP else ip_pkt.hlim
            self.fragment = ip_pkt.flags == 'MF' or ip_pkt.frag != 0 if self.type == PacketInfo.TYPE_IP else (IPv6ExtHdrFragment in ether_pkt)
            self.src_ip = ip_pkt.src
            self.dst_ip = ip_pkt.dst

            if self.protocol == PacketInfo.PROTOCOL_TCP:
                tcp_pkt = ip_pkt[TCP]

                self.flags = tcp_pkt.flags
                self.window = tcp_pkt.window
                self.ack = tcp_pkt.ack
                self.seq = tcp_pkt.seq

                self.protocol_length = len(tcp_pkt)
                self.payload = len(tcp_pkt) - (tcp_pkt.dataofs * 4)

            elif self.protocol == PacketInfo.PROTOCOL_UDP:
                udp_pkt = ip_pkt[UDP]

                self.protocol_length = len(udp_pkt)
                self.payload = len(udp_pkt) - (8 * 4)  # UDP header size is always 8

            elif self.protocol == PacketInfo.PROTOCOL_ICMP or \
                    self.protocol == PacketInfo.PROTOCOL_ICMPv6 or \
                    self.protocol == PacketInfo.PROTOCOL_IGMP:  # icmp
                self.payload = 0

            # elif self.type == PacketInfo.TYPE_IPv6 and ip_pkt.nh == 0 and ip_pkt.haslayer(HBHOptions):
            #     pass



            else:
                self.payload = self.protocol_length - (8 * 4)  # default is 8 bytes
                Log.log(f'Packet parameter is computing for non TCP and UDP packet type ({self.type_protocol_name} time = {pkt_time} packet = {ip_pkt}).',
                        logging.WARNING)
                if IPv6ExtHdrHopByHop in ip_pkt:
                    hop_by_hop_header = ip_pkt[IPv6ExtHdrHopByHop]
                    print("Hop-by-Hop Header:")
                    print(hop_by_hop_header.show())  # Display the Hop-by-Hop header details

                    # Access specific fields
                    # For example, if you want to access the options in the Hop-by-Hop header
                    if hop_by_hop_header.options:
                        for option in hop_by_hop_header.options:
                            print("Option Type:", option.type)
                            print("Option Data:", option.data)


        else:
            self.payload = self.protocol_length
            self.protocol = str(self.type)
            Log.log(f'Packet parameter is computing for unknown packet type {hex(self.type)}, time = {pkt_time}).',
                    logging.WARNING)

    def get_src(self):
        if self.is_ip_based():
            return self.src_ip
        else:
            return self.src_mac

    def get_dst(self):
        if self.is_ip_based():
            return self.dst_ip
        else:
            return self.dst_mac

    def is_ip_based(self):
        return self.type == PacketInfo.TYPE_IP or self.type == PacketInfo.TYPE_IPv6

    def is_tcp(self):
        return self.is_ip_based() and self.protocol == PacketInfo.PROTOCOL_TCP
    
    def get_flow_key(self):
        return (self.get_src(), self.get_dst(), self.protocol)
#%%
class Flow:
    def __init__(self, key):
        self.key = key
        self.src = key[0]
        self.dst = key[1]
        self.proto = key[2]
        self.timestamp = None
        self.sent_pkts = set()
        self.rec_pkts = set()
        _DIRECTION_SRC = 'src'
        _DIRECTION_DST = 'dst'
    def get(self):
        return {
            "srcip": self.src,#
            # "sport": self.sport,
            "dstip": self.dst,#
            # "dsport": self.dsport,
            "proto": self.proto,#
            # "state": self.state,
            "dur": self.get_dur(),#
            "sbytes": self.get_sbytes(),#
            "dbytes": self.get_dbytes(),#
            "sttl": self.get_sttl(),#
            "dttl": self.get_dttl(),#
            "sloss": self.get_sloss(),#
            "dloss": self.get_dloss(),#
            "service": self.service,
            # "Sload": self.Sload,
            # "Dload": self.Dload,
            "Spkts": self.get_Spkts(),#
            "Dpkts": self.get_Dpkts(),#
            "swin": self.get_swin(),#
            "dwin": self.get_dwin(),#
            # "stcpb": self.stcpb,
            # "dtcpb": self.dtcpb,
            # "smeansz": self.smeansz,
            # "dmeansz": self.dmeansz,
            # "trans_depth": self.trans_depth,
            # "res_bdy_len": self.res_bdy_len,
            # "Sjit": self.Sjit,
            # "Djit": self.Djit,
            # "Stime": self.Stime,
            # "Ltime": self.Ltime,
            # "Sintpkt": self.Sintpkt,
            # "Dintpkt": self.Dintpkt,
            # "tcprtt": self.tcprtt,
            # "synack": self.synack,
            # "ackdat": self.ackdat,
            # "is_sm_ips_ports": self.is_sm_ips_ports,
            # "ct_state_ttl": self.ct_state_ttl,
            # "ct_flw_http_mthd": self.ct_flw_http_mthd,
            # "is_ftp_login": self.is_ftp_login,
            # "ct_ftp_cmd": self.ct_ftp_cmd,
            # "ct_srv_src": self.ct_srv_src,
            # "ct_srv_dst": self.ct_srv_dst,
            # "ct_dst_ltm": self.ct_dst_ltm,
            # "ct_src_ltm": self.ct_src_ltm,
            # "ct_src_dport_ltm": self.ct_src_dport_ltm,
            # "ct_dst_sport_ltm": self.ct_dst_sport_ltm,
            # "ct_dst_src_ltm": self.ct_dst_src_ltm
        }
    @property
    def DIRECTION_SRC(self):
        return self._DIRECTION_SRC
    @property
    def DIRECTION_DST(self):
        return self._DIRECTION_DST
    def has_key(self, key):
        if self.proto != key[2]: return False
        if self.src == key[0] and self.dst == key[1]: return True
        if self.src == key[1] and self.dst == key[0]: return True
        return False
    def get_direction(self, key):
        if self.src == key[0] and self.dst == key[1]: return 1
        if self.src == key[1] and self.dst == key[0]: return 2
        return 0
    def get_src(self):
        return self.src
    def get_dst(self):
        return self.src
    def direction_to(self):
        return True if self.direction == 'dst' else False
    def add_packet(self, p_data: PacketParameter):
        print("Inside add")
        direction = self.get_direction(p_data.get_flow_key())
        print(direction)
        if direction == 1:
            self.sent_pkts.add(p_data)
            print("Packet added")
        elif direction == 2:
            self.rec_pkts.add(p_data)
        else:
            print("ELSE: " + str(direction))
            raise Exception("Wrong packet detected in add_packet method")
        
    def get_dur(self):
        return 1
    def get_sttl(self):
        sttl_list = [p.ttl for p in self.sent_pkts]
        return sum(sttl_list) / len(sttl_list)
    def get_dttl(self):
        dttl_list = [p.ttl for p in self.rec_pkts]
        return sum(dttl_list) / len(dttl_list)
    def get_swin(self):
        swin_list = [p.window for p in self.sent_pkts]
        return sum(swin_list) / len(swin_list)
    def get_dwin(self):
        dwin_list = [p.window for p in self.rec_pkts]
        return sum(dwin_list) / len(dwin_list)
    def get_sbytes(self):
        sbytes_list = [p.length for p in self.sent_pkts]
        return sum(sbytes_list)
    def get_dbytes(self):
        dbytes_list = [p.length for p in self.sent_pkts]
        return sum(dbytes_list)
    def get_Spkts(self):
        return len(self.sent_pkts)
    def get_Dpkts(self):
        return len(self.rec_pkts)
    def get_sloss(self):
        sseq_list = [p.seq for p in self.sent_pkts]
        return len(sseq_list) - len(list(dict.fromkeys(sseq_list)))
    def get_dloss(self):
        dseq_list = [p.seq for p in self.rec_pkts]
        return len(dseq_list) - len(list(dict.fromkeys(dseq_list)))

class FlowQueue:
    def __init__(self, interval = 0.5):
        self.interval = interval
        self.flows = []
    def store(self, packet: PacketParameter):
        print("Inside store")
        key = packet.get_flow_key()
        print("Inside store2")
        self.get_flow(key).add_packet(packet)
    def pop(self):
        return self.flows.pop()
    def get_flow(self, key):
        for flow in self.flows:
            if flow.has_key(key): return flow
        new_flow = Flow(key)
        self.flows.append(new_flow)
        return new_flow
#%%
flows_2 = {}
# def get_packet_info(packet):
#     info = {}
#     p_type = PacketInfo.get_packet_type(packet.type)
    
#     info['src_mac'] = packet.src
#     info['dst_mac'] = packet.dst
#     info['proto'] = packet[IP].proto
    
#     info['timestamp'] = packet.time
#     info['bytes'] = len(packet)
#     info['type'] = packet.type
#     info['type_protocol_name'] = PacketInfo.get_packet_type(packet.type)
#     info['protocol_length'] = len(packet) - 14
#     if p_type == PacketInfo.TYPE_IP or p_type == PacketInfo.TYPE_IPv6:
#         ip_pkt = packet[IP] if p_type == PacketInfo.TYPE_IP else packet[IPv6]
#         info['protocol_length'] -= (ip_pkt.ihl * 4 if p_type == PacketInfo.TYPE_IP else 40)
#         if p_type == PacketInfo.TYPE_IP:
#             proto = ip_pkt.proto
#         else:
#             if not ip_pkt.nh ==0:
#                 proto = ip_pkt.nh
#             else:
#                 if IPv6ExtHdrHopByHop in ip_pkt:
#                     hop_by_hop_header = ip_pkt[IPv6ExtHdrHopByHop]
#                     proto = hop_by_hop_header.nh
#                 else:
#                     proto = 0

#         info['protocol'] = PacketInfo.get_packet_protocol(proto)
#         info['type_protocol_name'] += ':' + info['protocol']
#         # info['src_ip'] = packet[IP].src
#         # info['dst_ip'] = packet[IP].dst
#         # info['sport'] = packet[TCP].sport
#         # info['dport'] = packet[TCP].dport
flows = FlowQueue()   
def process_packet(packet):
    print(packet.summary())
    p_data = PacketParameter(packet, packet.time)
    # print(p_data)
    flows.store(p_data)
    # if IP in packet:
    #     info = get_packet_info(packet)
        
    #     flow_key = (src_ip, dst_ip, proto)

    #     reverse_flow_key = (dst_ip, src_ip, proto)

        
    #     dur
    #     p_len = len(packet)
    #     if flow_key not in flows_2:
    #         flows_2[flow_key] = {sbytes: 0, dbytes: 0, sttl: [], dttl: [], Spkts: 0, Dpkts: 0}
    #     if reverse_flow_key not in flows_2:
    #         flows_2[reverse_flow_key] = {sbytes: 0, dbytes: 0, sttl: [], dttl: [], Spkts: 0, Dpkts: 0}

    #     # Update the counters
    #     flows_2[flow_key][sbytes] += len(packet)
    #     flows_2[reverse_flow_key][dbytes] += len(packet)
    #     flows_2[flow_key][Spkts] += 1
    #     flows_2[reverse_flow_key][Dpkts] += 1
    #     flows_2[flow_key][sttl].append(packet['IP'].ttl)
    #     flows_2[reverse_flow_key][dttl].append(packet['IP'].ttl)

# Sniff packets and process them
packets = sniff(iface='enp0s13f0u3', count=100, prn=process_packet)  # Adjust count as needed
print('Sniffing done')
# Print flow counts
# for flow, counts in flows_2.items():
#     print(f"Flow {flow}: S2D = {counts[sbytes]}, D2S = {counts[dbytes]}, Spkts = {counts[Spkts]}, Dpkts = {counts[Dpkts]}")
#%%
flow_data = pd.read_csv('/home/grauzone/projects/bakalarka/code/datasets/output_bottom.csv')
#%%
flow_data.columns
#%%
binary_payload = []
normal_payload = []
distributions = []
for packet in packets[:15]:
    if packet.haslayer('Raw'):
        # Check if the packet has a payload (Raw layer)
        # binary_payload.append(bytes(packet['Raw'].load))  # Extract payload as binary
        # normal_payload.append(packet['Raw'].load)
        raw_payload = bytes(packet['Raw'].load)
        print(raw_payload)
        byte_distribution = np.zeros(256)
        for byte in raw_payload:
            byte_distribution[byte] += 1
        total_bytes = len(raw_payload)
        if total_bytes > 0:
            byte_distribution = byte_distribution / total_bytes
        distributions.append(byte_distribution)
#%%
# Calculate mean, variance of the byte value distribution
# Feed it into a model to train
# bin_width - interval for M[X, y] to store variance and mean
class PayloadAnalyzer:
    def __init__(self, bin_width=5):
        self.bin_width = bin_width
        self.M = {}
    def fit(self, X, y):
        self.build_model(X)
        for packet in X:
            distribution = self.calculate_byte_distribution(packet)
            self.update_variance(len(packet), distribution)
            self.update_mean(len(packet), distribution)
            self.get_bin(len(packet))['count'] += 1 
            self.get_bin(len(packet))['distribution'] = distribution
        return self.M
    def predict(self, X):
        distribution = self.calculate_byte_distribution(X)
        instance = self.get_bin(len(X))
        normal_variance = instance['variance']
        normal_mean = instance['mean']
        return self.compute_anomaly_score(distribution, normal_mean, normal_variance)
        
    def compute_anomaly_score(self, distribution, mean, variance):
    # Assuming the distribution, mean, and variance are all vectors of the same size
    # Compute the Mahalanobis distance using the formula
        cov_matrix = np.diag(variance)  # Variance is assumed to be a diagonal matrix for simplicity
        cov_matrix_inv = np.linalg.inv(cov_matrix)  # Inverse of the covariance matrix
        delta = distribution - mean  # Difference between distribution and mean
        return mahalanobis(delta, np.zeros_like(delta), cov_matrix_inv)
    
    def build_model(self, X):
        # lengths = sort([len(payload) for payload in X]).unique()
        max_value = max([len(payload) for payload in X])
        keys = list(range(self.bin_width, max_value + self.bin_width, self.bin_width))
        bin_attributes = {}
        for key in keys:
            bin_attributes[key] = {
                'count': 0,
                'variance': 0,
                'mean': 0,
                'distribution': 0
            }
        self.M = bin_attributes
    
    def calculate_byte_distribution(self, packet):
        distribution = np.zeros(256)
        for byte in packet:
            distribution[byte] += 1
        packet_length = len(packet)
        if packet_length > 0:
            return distribution / packet_length
        return False
    
    def get_bin(self, length):
        if length % self.bin_width == 0:
            key = (length // self.bin_width) * self.bin_width
        else:
            key = ((length // self.bin_width) * self.bin_width) + self.bin_width
        # print(key)
        return self.M[key]
            
        
    def update_variance(self, length, new_variance):
        instance = self.get_bin(length)
        if instance['count'] == 0:
            instance['variance'] = np.var(new_variance)
        else:
            instance['variance'] = ((instance['variance'] * instance['count']) + (new_variance - instance['mean']) ** 2)/(instance['count'])
    
    def update_mean(self, length, new_mean):
        instance = self.get_bin(length)
        # print(instance)
        if instance['count'] == 0:
            instance['mean'] = np.mean(new_mean)
        else:
            # ((instance['count']) * instance['variance']) + ((n2 - 1) * var2) + (n1 * n2 / (n1 + n2)) * (mu1 - mu2)**2
            instance['mean'] = (instance['mean']*instance['count']+new_mean)/(instance['count'] + 1)
    def get_length_distribution(self):
        return [val['count'] for val in self.M.values()]
    def get_variance(self, length):
        return self.get_bin(length)['variance']
    def get_mean(self, length):
        return self.get_bin(length)['mean']
#%%
normal_payload = []
for packet in packets:
    if packet.haslayer('Raw'):
        normal_payload.append(bytes(packet['Raw'].load))
#%%
analyzer = PayloadAnalyzer()
analyzer.fit(normal_payload[1:], {})

# print(analyzer.predict(normal_payload[0]))
#%%
c = analyzer.M[100]['distribution']
# c = [val['count'] for val in analyzer.M.values()]
# r = analyzer.M.keys()
r = list(range(256))
plt.bar(r, c, width=1.5, color='yellowgreen')
plt.gca().patch.set_facecolor('slategray')  # Set axes background to black
plt.show()
#%%
cov_matrix = np.diag(analyzer.M[5]['variance'])  # Variance is assumed to be a diagonal matrix for simplicity
# cov_matrix_inv = np.linalg.inv(cov_matrix)  # Inverse of the covariance matrix
# delta = distribution - mean  # Difference between distribution and mean
# return mahalanobis(delta, np.zeros_like(delta), cov_matrix_inv)
#%%
def generate_ngrams(payload, n):
    return [payload[i:i+n] for i in range(len(payload) - n + 1)]
#%%
import hashlib

class BloomFilterX:
    def __init__(self, size, hash_count):
        self.size = size  # The size of the bit array
        self.hash_count = hash_count  # Number of hash functions
        self.bit_array = [0] * self.size  # Initialize a bit array with 0s
        self.count_array = [0] * self.size  # Array to count how many times a position is set

    def _hash(self, item, seed):
        """Generate a hash value for an item using a specific seed."""
        return hashlib.md5(str(seed).encode('utf-8') + item).hexdigest()

    def add(self, item):
        """Add an item to the Bloom filter by updating the count array."""
        for i in range(self.hash_count):
            hash_value = self._hash(item, i)
            bit_position = int(hash_value, 16) % self.size
            self.bit_array[bit_position] = 1  # Mark the bit as set
            self.count_array[bit_position] += 1  # Increment the count for that bit position

    def contains(self, item):
        """Check if an item is in the Bloom filter by evaluating the count array."""
        for i in range(self.hash_count):
            hash_value = self._hash(item, i)
            bit_position = int(hash_value, 16) % self.size
            if self.count_array[bit_position] == 0:
                return False  # If count is 0, the item definitely doesn't exist
        return True

    def get_distribution(self):
        """Return the distribution (counts) of how many times positions have been set."""
        return self.count_array

    def analyze_attack(self, threshold):
        """Determine if the Bloom filter suggests the presence of an attack."""
        suspicious_count = sum(1 for count in self.count_array if count > threshold)
        if suspicious_count > len(self.count_array) * 0.1:  # If more than 10% of the bits have been set unusually often
            return "Potential attack detected"
        return "No attack detected"
    def compare(self, other_bloom_filter):
        """Compare this BloomFilterX with another BloomFilterX."""
        # Compare the bit arrays
        bit_array_diff = sum(1 for a, b in zip(self.bit_array, other_bloom_filter.bit_array) if a != b)

        # Compare the count arrays using Chi-Squared test (this assumes count arrays are the same length)
        chi_squared_stat, p_value = chisquare(self.count_array, other_bloom_filter.count_array)

        return {
            "bit_array_diff": bit_array_diff,
            "chi_squared_stat": chi_squared_stat,
            "p_value": p_value
        }
#%%
def hash1(data):
    return hashlib.md5(data)

def hash2(data):
    return hashlib.sha256(data)

# Add more hash functions if needed
hash_functions = [hash1, hash2]
#%%
payloads = normal_payload[:1000]  # Example payloads
bloom = BloomFilterX(size=1000, hash_count=3)

for payload in payloads:
    ngrams = generate_ngrams(payload, n=3)  # Generate 3-grams
    for ngram in ngrams:
        bloom.add(ngram)
#%%
new_payload = normal_payload[300]
ngrams = generate_ngrams(new_payload, n=3)

for ngram in ngrams:
    print(f"N-gram {ngram} legitimacy score: {bloom_filter.query(ngram)}")
#%%
bloom_current = BloomFilterX(size=1000, hash_count=3)
bloom_previous = BloomFilterX(size=1000, hash_count=3)
for payload in payloads:
        ngrams = generate_ngrams(payload, n=3)
        for ngram in ngrams:
            bloom_current.add(ngram)
            
            
for payload in normal_payload[1001:2001]:
        ngrams = generate_ngrams(payload, n=3)
        for ngram in ngrams:
            bloom_previous.add(ngram)
            
delta = bloom_current.compare(bloom_previous)
print(f"Delta: {delta}")
#%%
print(sum(abs(bloom_current.get_distribution()[i] - bloom_previous.get_distribution()[i]) for i in range(1000)) / 1000)