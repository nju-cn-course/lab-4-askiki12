#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.logging import *

class RebuildPkt:
    def __init__(self, pkt, subnet, port, targetip):
        self.packet = pkt
        self.recent_time = time.time()
        self.num_of_retries = 0
        self.match_subnet = subnet
        self.send_out_port = port
        self.targetipaddress = targetip

    def get_targetipaddress(self):
        return self.targetipaddress

    def get_send_out_port(self):
        return self.send_out_port

    def get_packet(self):
        return self.packet

    def get_num_of_retries(self):
        return self.num_of_retries

    def try_to_send(self):
        self.num_of_retries += 1

    def update_time(self):
        self.recent_time = time.time()

    def get_recent_time(self):
        return self.recent_time


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = net.interfaces()
        self.arp_table = {}
        self.ip_list = []
        self.eth_list = []
        for i in self.interfaces:
            self.ip_list.append(i.ipaddr)
            self.eth_list.append(i.ethaddr)
        self.forwarding_table = {}
        for i in self.interfaces:
            sub_network_address = IPv4Address(ip_address((int(i.ipaddr) & int(i.netmask))))
            self.forwarding_table[sub_network_address] = [i.netmask, '0.0.0.0', i.name]

        with open('forwarding_table.txt') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                else:
                    table_info = line.split()
                    self.forwarding_table[IPv4Address(table_info[0])] = [IPv4Address(table_info[1]),
                                                                         IPv4Address(table_info[2]), table_info[3]]
        self.packet_queue = []
        self.arp_timeout = 20*60


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        input_port = self.net.interface_by_name(ifaceName)

        if arp is not None:
            self.update_arp_table()
            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
            if arp.operation == ArpOperation.Request:
                for i in self.ip_list:
                    if i == arp.targetprotoaddr:
                        arp_reply_pkt = create_ip_arp_reply(input_port.ethaddr, arp.senderhwaddr, arp.targetprotoaddr,
                                                            arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, arp_reply_pkt)
                        log_info(f"Sending arp reply {arp_reply_pkt} to {ifaceName}")
                        return
            else:
                self.forwarding()
                return
        elif ipv4 is not None:
            if ipv4.dst in self.ip_list:
                return
            match_subnet, next_hop_ip, out_port = self.longest_prefix_match(ipv4.dst)
            if match_subnet:
                ipv4.ttl -= 1
                if ipv4.ttl <= 0:
                    return
                if next_hop_ip == '0.0.0.0':
                    dstip = ipv4.dst
                else:
                    dstip = next_hop_ip
                pkt = RebuildPkt(packet, match_subnet, out_port, dstip)
                self.packet_queue.append(pkt)
                self.forwarding()

    def update_arp_table(self):
        current_time = time.time()
        for ip in list(self.arp_table.keys()):
            mac, last_update_time = self.arp_table[ip]
            if current_time - last_update_time > self.arp_timeout:
                del self.arp_table[ip]

    def longest_prefix_match(self, dst_ip):
        best_match = None
        best_prefix_len = 0
        next_hop_ip = None
        out_port = None
        for prefix, (netmask, next_hop, port) in self.forwarding_table.items():
            net = IPv4Network(str(prefix) + '/' + str(netmask))
            if dst_ip in net:
                if net.prefixlen > best_prefix_len:
                    best_prefix_len = net.prefixlen
                    best_match = prefix
                    next_hop_ip = next_hop
                    out_port = port
        return best_match, next_hop_ip, out_port

    def forwarding(self):
        if len(self.packet_queue) == 0:
            return
        handle_pkt = self.packet_queue[0]
        targetipaddr = handle_pkt.get_targetipaddress()
        router_send_to_host_port_name = handle_pkt.get_send_out_port()
        my_packet = handle_pkt.get_packet()
        router_forwarding_port_info = self.net.interface_by_name(router_send_to_host_port_name)
        if targetipaddr in self.arp_table.keys():
            self.forwarding_packet(my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info)
        elif handle_pkt.get_num_of_retries() < 5:
            self.send_arp_request(handle_pkt, router_forwarding_port_info, targetipaddr, router_send_to_host_port_name)
        elif handle_pkt.get_num_of_retries() >= 5:
            del (self.packet_queue[0])


    def forwarding_packet(self, my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info):
        my_packet[Ethernet].src = router_forwarding_port_info.ethaddr
        my_packet[Ethernet].dst = self.arp_table[targetipaddr][0]
        self.net.send_packet(router_send_to_host_port_name, my_packet)
        log_info(f"Forwarding packet {my_packet} to {router_send_to_host_port_name}")
        del (self.packet_queue[0])

    def send_arp_request(self, handle_pkt, router_if, targetip, portname):
        if handle_pkt.get_num_of_retries() == 0 or (time.time() - handle_pkt.get_recent_time()) > 1.0:
            arppacket = create_ip_arp_request(
                router_if.ethaddr, router_if.ipaddr, targetip)
            handle_pkt.try_to_send()
            handle_pkt.update_time()
            self.net.send_packet(portname, arppacket)
            log_info(f"Sending arp request {arppacket} to {portname}")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.forwarding()
                continue
            except Shutdown:
                break
            log_info("handle_packet")
            self.handle_packet(recv)
            self.forwarding()

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
