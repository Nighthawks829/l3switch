from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
import subprocess
import ipaddress


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(L3Switch, self).__init__(*_args, **_kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.port_to_ip = {}
        self.route_table = {}

    # Run the subprocess to get the IP address for each OpenVSwitch Interface
    def get_switch_ips(self, switch_name):
        ip_dict = {}

        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True,
            text=True,
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            iface = parts[1]  # s1-eth1
            if not iface.startswith(f"{switch_name}-eth"):
                continue

            ip_prefix = parts[3]  # 192.168.1.1/24
            ip_intf = ipaddress.IPv4Interface(ip_prefix)

            # self.logger.info("IP Intf: %s", ip_intf)
            self.logger.info(ip_prefix)

            ip_dict[iface] = {
                "ip": str(ip_intf.ip),
                "netmask": str(ip_intf.netmask),
                "network": str(ip_intf.network.network_address),
                "prefixlen": ip_intf.network.prefixlen,
            }

        return ip_dict

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.logger.info("Switch %s connected", dpid)

        switch_ips = self.get_switch_ips(f"s{dpid}")
        self.logger.info("Switch %s IPs: %s", dpid, switch_ips)

        # Build the Port to IP Table
        self.port_to_ip.setdefault(dpid, {})

        for iface, data in switch_ips.items():
            ip = data["ip"]

            # Extract port number from interface name (s1-eth1 → 1)
            port_no = int(iface.split("eth")[1])

            self.port_to_ip[dpid][port_no] = ip

            self.logger.info("Mapped DPID=%s Port=%s -> IP=%s", dpid, port_no, ip)

        self.logger.info("Port to IP: %s", self.port_to_ip)

        # Build Route Table
        self.route_table.setdefault(dpid, [])

        for iface, data in switch_ips.items():
            network = data["network"]
            netmask = data["netmask"]
            prefixlen = data["prefixlen"]

            port_no = int(iface.split("eth")[1])

            route_entry = {
                "network": network,
                "netmask": netmask,
                "prefixlen": prefixlen,
                "port": port_no,
            }

            self.route_table[dpid].append(route_entry)

            self.logger.info(
                "Route added: %s/%s -> port %s", network, prefixlen, port_no
            )

        self.logger.info("Route Table: %s", self.route_table)

        # Build Broadcast Flow
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

        # Build Route Table Flow

        # for route in self.route_table[dpid]:
        #     network = route["network"]
        #     netmask = route["netmask"]
        #     port = route["port"]

        #     match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(network, netmask))

        #     actions = [parser.OFPActionOutput(port)]

        #     self.add_flow(datapath, priority=100, match=match, actions=actions)

        #     self.logger.info(
        #         "Installed route: %s/%s -> port %s",
        #         network,
        #         route["prefixlen"],
        #         port,
        #     )

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        self.logger.info("Sent OFPPortDescStatsRequest to switch dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.logger.info(ev.msg.body)
        datapath = ev.msg.datapath
        dpid = datapath.id

        # Initialize dictionary if needed
        if not hasattr(self, "ip_to_mac"):
            self.ip_to_mac = {}

        # Hardcoded IPs per port for this switch
        # switch_port_ip = {
        #     1: "192.168.1.1",  # port 1 → IP 192.168.1.1
        #     2: "192.168.2.1",  # port 2 → IP 192.168.2.1
        # }

        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info("---- Switch %s Port Information ----", dpid)
        for p in ev.msg.body:
            if p.port_no == datapath.ofproto.OFPP_LOCAL:
                continue
            port_no = p.port_no
            name = p.name.decode("utf-8")
            mac = p.hw_addr
            state = p.state
            curr_speed = p.curr_speed
            max_speed = p.max_speed

            self.logger.info(
                "DPID=%s | Port=%s | Name=%s | MAC=%s | State=%s | Speed=%s Mbps",
                dpid,
                port_no,
                name,
                mac,
                state,
                curr_speed,
            )

            if dpid in self.port_to_ip and port_no in self.port_to_ip[dpid]:
                ip = self.port_to_ip[dpid][port_no]
                self.ip_to_mac[dpid][ip] = mac
                self.logger.info(
                    "Switch %s Port %s: IP=%s MAC=%s", dpid, port_no, ip, mac
                )

            self.logger.info(self.ip_to_mac)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match["in_port"]

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #     arp_pkt = pkt.get_protocol(arp.arp)

    #     # self.logger.info("ETH %s",eth)
    #     # if arp_pkt:
    #     #     self.logger.info(arp_pkt)
    #     #     self.logger.info(
    #     #         "ARP Packet received: %s -> %s (target IP %s)",
    #     #         arp_pkt.src_ip,
    #     #         arp_pkt.dst_ip,
    #     #         arp_pkt.dst_ip,
    #     #     )
    #     # # Here you can handle ARP reply
    #     # else:
    #     #     self.logger.debug("Not an ARP packet, ignoring")
    #     # if eth.ethertype==ether_types.ETH_TYPE_ARP:
    #     #     self.logger.info("%s",)

    #     # Handle ARP requests
    #     if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
    #         target_ip = arp_pkt.dst_ip
    #         dpid = datapath.id

    #         if dpid in self.ip_to_mac and target_ip in self.ip_to_mac[dpid]:
    #             mac_to_reply = self.ip_to_mac[dpid][target_ip]
    #             src_mac = mac_to_reply

    #             # Build ARP Reply
    #             arp_reply_pkt = packet.Packet()
    #             arp_reply_pkt.add_protocol(
    #                 ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=src_mac)
    #             )

    #             arp_reply_pkt.add_protocol(
    #                 arp.arp(
    #                     opcode=arp.ARP_REPLY,
    #                     src_mac=src_mac,
    #                     src_ip=target_ip,
    #                     dst_mac=arp_pkt.src_mac,
    #                     dst_ip=arp_pkt.src_ip,
    #                 )
    #             )

    #             arp_reply_pkt.serialize()

    #             actions = [parser.OFPActionOutput(in_port)]
    #             out = parser.OFPPacketOut(
    #                 datapath=datapath,
    #                 buffer_id=ofproto.OFP_NO_BUFFER,
    #                 in_port=ofproto.OFPP_CONTROLLER,
    #                 actions=actions,
    #                 data=arp_reply_pkt.data,
    #             )
    #             datapath.send_msg(out)

    #             self.logger.info(
    #                 "Sent ARP reply: IP=%s MAC=%s to port %s",
    #                 target_ip,
    #                 mac_to_reply,
    #                 in_port,
    #             )

    #     # Handle ICMP Echo requests (ping)
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #     icmp_pkt = pkt.get_protocol(icmp.icmp)

    #     if ip_pkt and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
    #         # self.logger.info("IP: %s", ip_pkt)
    #         # self.logger.info("ICMP: %s", icmp_pkt)
    #         dpid = datapath.id
    #         dst_ip = ip_pkt.dst
    #         if dpid in self.ip_to_mac and dst_ip in self.ip_to_mac[dpid]:
    #             src_mac = self.ip_to_mac[dpid][dst_ip]

    #             # Build ICMP Echo Reply
    #             icmp_reply = packet.Packet()
    #             icmp_reply.add_protocol(
    #                 ethernet.ethernet(ethertype=eth.ethertype, src=src_mac, dst=eth.src)
    #             )

    #             icmp_reply.add_protocol(
    #                 ipv4.ipv4(dst=ip_pkt.src, src=dst_ip, proto=ip_pkt.proto)
    #             )

    #             icmp_reply.add_protocol(
    #                 icmp.icmp(
    #                     type_=icmp.ICMP_ECHO_REPLY,
    #                     code=0,
    #                     csum=0,
    #                     data=icmp_pkt.data,
    #                 )
    #             )

    #             icmp_reply.serialize()

    #             actions = [parser.OFPActionOutput(in_port)]
    #             out = parser.OFPPacketOut(
    #                 datapath=datapath,
    #                 buffer_id=ofproto.OFP_NO_BUFFER,
    #                 in_port=ofproto.OFPP_CONTROLLER,
    #                 actions=actions,
    #                 data=icmp_reply.data,
    #             )
    #             datapath.send_msg(out)
    #             self.logger.info(
    #                 "Sent ICMP reply: IP=%s to %s on port %s",
    #                 dst_ip,
    #                 ip_pkt.src,
    #                 in_port,
    #             )

    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         return
    #     dst = eth.dst
    #     src = eth.src

    #     dpid = datapath.id
    #     self.mac_to_port.setdefault(dpid, {})

    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

    #     self.mac_to_port[dpid][src] = in_port

    #     if dst in self.mac_to_port[dpid]:
    #         out_port = self.mac_to_port[dpid][dst]
    #     else:
    #         out_port = ofproto.OFPP_FLOOD

    #     actions = [parser.OFPActionOutput(out_port)]

    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

    #         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
    #             self.add_flow(datapath, 1, match, actions, msg.buffer_id)
    #             return
    #         else:
    #             self.add_flow(datapath, 1, match, actions)

    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data

    #     out = parser.OFPPacketOut(
    #         datapath=datapath,
    #         buffer_id=msg.buffer_id,
    #         in_port=in_port,
    #         actions=actions,
    #         data=data,
    #     )

    #     datapath.send_msg(out)

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     in_port = msg.match["in_port"]
    #     dpid = datapath.id

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #     arp_pkt = pkt.get_protocol(arp.arp)
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #     icmp_pkt = pkt.get_protocol(icmp.icmp)

    #     # --- ARP Handling ---
    #     if arp_pkt:
    #         # Learn sender IP→MAC mapping
    #         self.ip_to_mac.setdefault(dpid, {})
    #         self.ip_to_mac[dpid][arp_pkt.src_ip] = arp_pkt.src_mac
    #         self.logger.info("Learned: IP=%s MAC=%s", arp_pkt.src_ip, arp_pkt.src_mac)

    #         if arp_pkt.opcode == arp.ARP_REQUEST:
    #             target_ip = arp_pkt.dst_ip

    #             if target_ip in self.ip_to_mac.get(dpid, {}):
    #                 mac_to_reply = self.ip_to_mac[dpid][target_ip]

    #                 arp_reply_pkt = packet.Packet()
    #                 arp_reply_pkt.add_protocol(
    #                     ethernet.ethernet(
    #                         ethertype=eth.ethertype, dst=eth.src, src=mac_to_reply
    #                     )
    #                 )
    #                 arp_reply_pkt.add_protocol(
    #                     arp.arp(
    #                         opcode=arp.ARP_REPLY,
    #                         src_mac=mac_to_reply,
    #                         src_ip=target_ip,
    #                         dst_mac=arp_pkt.src_mac,
    #                         dst_ip=arp_pkt.src_ip,
    #                     )
    #                 )
    #                 arp_reply_pkt.serialize()

    #                 actions = [parser.OFPActionOutput(in_port)]
    #                 out = parser.OFPPacketOut(
    #                     datapath=datapath,
    #                     buffer_id=ofproto.OFP_NO_BUFFER,
    #                     in_port=ofproto.OFPP_CONTROLLER,
    #                     actions=actions,
    #                     data=arp_reply_pkt.data,
    #                 )
    #                 datapath.send_msg(out)
    #                 self.logger.info(
    #                     "Sent ARP reply: IP=%s MAC=%s to port %s",
    #                     target_ip,
    #                     mac_to_reply,
    #                     in_port,
    #                 )
    #         return  # Stop here, ARP fully handled

    #     # --- ICMP ping to switch's own interface IP ---
    #     if ip_pkt and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
    #         # self.logger.info("ICMP Ping to SWitch Own Interface", ip_pkt.dst)
    #         dst_ip = ip_pkt.dst
    #         if dst_ip in self.ip_to_mac.get(dpid, {}):
    #             src_mac = self.ip_to_mac[dpid][dst_ip]

    #             icmp_reply = packet.Packet()
    #             icmp_reply.add_protocol(
    #                 ethernet.ethernet(ethertype=eth.ethertype, src=src_mac, dst=eth.src)
    #             )
    #             icmp_reply.add_protocol(
    #                 ipv4.ipv4(dst=ip_pkt.src, src=dst_ip, proto=ip_pkt.proto)
    #             )
    #             icmp_reply.add_protocol(
    #                 icmp.icmp(
    #                     type_=icmp.ICMP_ECHO_REPLY,
    #                     code=0,
    #                     csum=0,
    #                     data=icmp_pkt.data,
    #                 )
    #             )
    #             icmp_reply.serialize()

    #             actions = [parser.OFPActionOutput(in_port)]
    #             out = parser.OFPPacketOut(
    #                 datapath=datapath,
    #                 buffer_id=ofproto.OFP_NO_BUFFER,
    #                 in_port=ofproto.OFPP_CONTROLLER,
    #                 actions=actions,
    #                 data=icmp_reply.data,
    #             )
    #             datapath.send_msg(out)
    #             self.logger.info(
    #                 "Sent ICMP reply: IP=%s to %s on port %s",
    #                 dst_ip,
    #                 ip_pkt.src,
    #                 in_port,
    #             )
    #             return  # Stop here, ICMP fully handled

    #     # --- L3 Routing with MAC rewrite (cross-subnet) ---
    #     if ip_pkt:
    #         self.logger.info("L3 Routing")
    #         dst_ip = ip_pkt.dst

    #         # Find output port from route table
    #         out_port = None
    #         for route in self.route_table.get(dpid, []):
    #             network = ipaddress.IPv4Network(
    #                 f"{route['network']}/{route['prefixlen']}"
    #             )
    #             if ipaddress.IPv4Address(dst_ip) in network:
    #                 out_port = route["port"]
    #                 break

    #         if out_port is None:
    #             self.logger.warning("No route found for %s", dst_ip)
    #             return

    #         # Check if we know the destination host MAC
    #         dst_mac = self.ip_to_mac.get(dpid, {}).get(dst_ip)
    #         if dst_mac is None:
    #             # We don't know dst MAC yet — send ARP request to learn it
    #             self.logger.info("Unknown MAC for %s, sending ARP request", dst_ip)
    #             src_ip = self.port_to_ip[dpid].get(out_port)
    #             src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip)

    #             if src_ip and src_mac:
    #                 arp_req = packet.Packet()
    #                 arp_req.add_protocol(
    #                     ethernet.ethernet(
    #                         ethertype=ether_types.ETH_TYPE_ARP,
    #                         dst="ff:ff:ff:ff:ff:ff",
    #                         src=src_mac,
    #                     )
    #                 )
    #                 arp_req.add_protocol(
    #                     arp.arp(
    #                         opcode=arp.ARP_REQUEST,
    #                         src_mac=src_mac,
    #                         src_ip=src_ip,
    #                         dst_mac="00:00:00:00:00:00",
    #                         dst_ip=dst_ip,
    #                     )
    #                 )
    #                 arp_req.serialize()
    #                 actions = [parser.OFPActionOutput(out_port)]
    #                 out = parser.OFPPacketOut(
    #                     datapath=datapath,
    #                     buffer_id=ofproto.OFP_NO_BUFFER,
    #                     in_port=ofproto.OFPP_CONTROLLER,
    #                     actions=actions,
    #                     data=arp_req.data,
    #                 )
    #                 datapath.send_msg(out)
    #             return

    #         # We know dst MAC — rewrite Ethernet header and forward
    #         src_ip_of_out_port = self.port_to_ip[dpid].get(out_port, "")
    #         new_src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip_of_out_port, eth.src)

    #         actions = [
    #             parser.OFPActionSetField(
    #                 eth_src=new_src_mac
    #             ),  # rewrite src to gateway port MAC
    #             parser.OFPActionSetField(
    #                 eth_dst=dst_mac
    #             ),  # rewrite dst to actual host MAC
    #             parser.OFPActionOutput(out_port),
    #         ]
    #         out = parser.OFPPacketOut(
    #             datapath=datapath,
    #             buffer_id=ofproto.OFP_NO_BUFFER,
    #             in_port=in_port,
    #             actions=actions,
    #             data=msg.data,
    #         )
    #         datapath.send_msg(out)
    #         self.logger.info(
    #             "Routed: %s -> %s via port %s | src_mac=%s dst_mac=%s",
    #             ip_pkt.src,
    #             dst_ip,
    #             out_port,
    #             new_src_mac,
    #             dst_mac,
    #         )
    #         return

    #     # --- L2 Fallback (same subnet / non-IP) ---
    #     if eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         return

    #     dst = eth.dst
    #     src = eth.src
    #     self.mac_to_port.setdefault(dpid, {})
    #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
    #     self.mac_to_port[dpid][src] = in_port

    #     if dst in self.mac_to_port[dpid]:
    #         out_port = self.mac_to_port[dpid][dst]
    #     else:
    #         out_port = ofproto.OFPP_FLOOD

    #     actions = [parser.OFPActionOutput(out_port)]

    #     if out_port != ofproto.OFPP_FLOOD:
    #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
    #         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
    #             self.add_flow(datapath, 1, match, actions, msg.buffer_id)
    #             return
    #         else:
    #             self.add_flow(datapath, 1, match, actions)

    #     data = None
    #     if msg.buffer_id == ofproto.OFP_NO_BUFFER:
    #         data = msg.data

    #     out = parser.OFPPacketOut(
    #         datapath=datapath,
    #         buffer_id=msg.buffer_id,
    #         in_port=in_port,
    #         actions=actions,
    #         data=data,
    #     )
    #     datapath.send_msg(out)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # --- ARP Handling ---
        if arp_pkt:
            # Learn sender IP→MAC mapping
            self.ip_to_mac.setdefault(dpid, {})
            self.ip_to_mac[dpid][arp_pkt.src_ip] = arp_pkt.src_mac
            self.logger.info("Learned: IP=%s MAC=%s", arp_pkt.src_ip, arp_pkt.src_mac)

            if arp_pkt.opcode == arp.ARP_REQUEST:
                target_ip = arp_pkt.dst_ip

                if target_ip in self.ip_to_mac.get(dpid, {}):
                    mac_to_reply = self.ip_to_mac[dpid][target_ip]

                    arp_reply_pkt = packet.Packet()
                    arp_reply_pkt.add_protocol(
                        ethernet.ethernet(
                            ethertype=eth.ethertype,
                            dst=eth.src,
                            src=mac_to_reply
                        )
                    )
                    arp_reply_pkt.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=mac_to_reply,
                            src_ip=target_ip,
                            dst_mac=arp_pkt.src_mac,
                            dst_ip=arp_pkt.src_ip,
                        )
                    )
                    arp_reply_pkt.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_reply_pkt.data,
                    )
                    datapath.send_msg(out)
                    self.logger.info(
                        "Sent ARP reply: IP=%s MAC=%s to port %s",
                        target_ip, mac_to_reply, in_port,
                    )

            # After ARP, check if we can now install a pending L3 flow
            # e.g. h2 just replied ARP, now we know h2's MAC → install flow
            self._try_install_l3_flow(datapath, dpid, arp_pkt.src_ip)
            return

        # --- ICMP ping to switch's own interface IP ---
        if ip_pkt and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            dst_ip = ip_pkt.dst
            if dst_ip in self.ip_to_mac.get(dpid, {}):
                src_mac = self.ip_to_mac[dpid][dst_ip]

                icmp_reply = packet.Packet()
                icmp_reply.add_protocol(
                    ethernet.ethernet(ethertype=eth.ethertype, src=src_mac, dst=eth.src)
                )
                icmp_reply.add_protocol(
                    ipv4.ipv4(dst=ip_pkt.src, src=dst_ip, proto=ip_pkt.proto)
                )
                icmp_reply.add_protocol(
                    icmp.icmp(
                        type_=icmp.ICMP_ECHO_REPLY,
                        code=0,
                        csum=0,
                        data=icmp_pkt.data,
                    )
                )
                icmp_reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=icmp_reply.data,
                )
                datapath.send_msg(out)
                self.logger.info(
                    "Sent ICMP reply: IP=%s to %s on port %s",
                    dst_ip, ip_pkt.src, in_port,
                )
                return

        # --- L3 Routing with proactive flow installation ---
        if ip_pkt:
            dst_ip = ip_pkt.dst

            # Find output port from route table
            out_port = None
            for route in self.route_table.get(dpid, []):
                network = ipaddress.IPv4Network(
                    f"{route['network']}/{route['prefixlen']}"
                )
                if ipaddress.IPv4Address(dst_ip) in network:
                    out_port = route["port"]
                    break

            if out_port is None:
                self.logger.warning("No route found for %s", dst_ip)
                return

            dst_mac = self.ip_to_mac.get(dpid, {}).get(dst_ip)

            if dst_mac is None:
                # Don't know dst MAC yet — send ARP request and buffer this dst_ip
                self.logger.info("Unknown MAC for %s, sending ARP request", dst_ip)

                # Save pending dst_ip so we install flow once ARP reply comes
                self.pending_routes = getattr(self, "pending_routes", {})
                self.pending_routes.setdefault(dpid, set()).add(dst_ip)

                src_ip = self.port_to_ip[dpid].get(out_port)
                src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip)

                if src_ip and src_mac:
                    arp_req = packet.Packet()
                    arp_req.add_protocol(
                        ethernet.ethernet(
                            ethertype=ether_types.ETH_TYPE_ARP,
                            dst="ff:ff:ff:ff:ff:ff",
                            src=src_mac,
                        )
                    )
                    arp_req.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REQUEST,
                            src_mac=src_mac,
                            src_ip=src_ip,
                            dst_mac="00:00:00:00:00:00",
                            dst_ip=dst_ip,
                        )
                    )
                    arp_req.serialize()
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_req.data,
                    )
                    datapath.send_msg(out)
                return

            # We know dst MAC — install a FLOW RULE with MAC rewrite into OVS
            # OVS will handle all future packets without hitting the controller
            src_ip_of_out_port = self.port_to_ip[dpid].get(out_port, "")
            new_src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip_of_out_port, eth.src)

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=dst_ip,  # match exact host IP
            )
            actions = [
                parser.OFPActionSetField(eth_src=new_src_mac),
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionOutput(out_port),
            ]
            # Install with priority=200 so it beats the table-miss rule
            self.add_flow(datapath, priority=200, match=match, actions=actions)
            self.logger.info(
                "Installed L3 flow: dst=%s -> port=%s src_mac=%s dst_mac=%s",
                dst_ip, out_port, new_src_mac, dst_mac,
            )

            # Also forward this first packet immediately (don't drop it)
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # --- L2 Fallback ---
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # --- Helper: install L3 flow once ARP reply teaches us a MAC ---
    def _try_install_l3_flow(self, datapath, dpid, learned_ip):
        pending = getattr(self, "pending_routes", {}).get(dpid, set())
        if learned_ip not in pending:
            return

        parser = datapath.ofproto_parser

        # Find which port this IP belongs to
        out_port = None
        for route in self.route_table.get(dpid, []):
            network = ipaddress.IPv4Network(
                f"{route['network']}/{route['prefixlen']}"
            )
            if ipaddress.IPv4Address(learned_ip) in network:
                out_port = route["port"]
                break

        if out_port is None:
            return

        dst_mac = self.ip_to_mac.get(dpid, {}).get(learned_ip)
        src_ip_of_out_port = self.port_to_ip[dpid].get(out_port, "")
        new_src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip_of_out_port)

        if not dst_mac or not new_src_mac:
            return

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=learned_ip,
        )
        actions = [
            parser.OFPActionSetField(eth_src=new_src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port),
        ]
        self.add_flow(datapath, priority=200, match=match, actions=actions)
        self.logger.info(
            "Proactively installed L3 flow for %s -> port=%s dst_mac=%s",
            learned_ip, out_port, dst_mac,
        )

        # Remove from pending
        self.pending_routes[dpid].discard(learned_ip)