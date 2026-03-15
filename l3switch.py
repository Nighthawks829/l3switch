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


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(L3Switch, self).__init__(*_args, **_kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

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
        switch_port_ip = {
            1: "192.168.1.1",  # port 1 → IP 192.168.1.1
            2: "192.168.2.1",  # port 2 → IP 192.168.2.1
        }

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

            if port_no in switch_port_ip:
                ip = switch_port_ip[port_no]
                mac = mac
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        # self.logger.info("ETH %s",eth)
        # if arp_pkt:
        #     self.logger.info(arp_pkt)
        #     self.logger.info(
        #         "ARP Packet received: %s -> %s (target IP %s)",
        #         arp_pkt.src_ip,
        #         arp_pkt.dst_ip,
        #         arp_pkt.dst_ip,
        #     )
        # # Here you can handle ARP reply
        # else:
        #     self.logger.debug("Not an ARP packet, ignoring")
        # if eth.ethertype==ether_types.ETH_TYPE_ARP:
        #     self.logger.info("%s",)

        # Handle ARP requests
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            dpid = datapath.id

            if dpid in self.ip_to_mac and target_ip in self.ip_to_mac[dpid]:
                mac_to_reply = self.ip_to_mac[dpid][target_ip]
                src_mac = mac_to_reply

                # Build ARP Reply
                arp_reply_pkt = packet.Packet()
                arp_reply_pkt.add_protocol(
                    ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=src_mac)
                )

                arp_reply_pkt.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=src_mac,
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
                    target_ip,
                    mac_to_reply,
                    in_port,
                )

        # Handle ICMP Echo requests (ping)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            # self.logger.info("IP: %s", ip_pkt)
            # self.logger.info("ICMP: %s", icmp_pkt)
            dpid = datapath.id
            dst_ip = ip_pkt.dst
            if dpid in self.ip_to_mac and dst_ip in self.ip_to_mac[dpid]:
                src_mac = self.ip_to_mac[dpid][dst_ip]

                # Build ICMP Echo Reply
                icmp_reply = packet.Packet()
                icmp_reply.add_protocol(
                    ethernet.ethernet(
                        ethertype=eth.ethertype, src=src_mac, dst=eth.src
                    )
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
                    dst_ip,
                    ip_pkt.src,
                    in_port,
                )

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port, eth_dst=dst, eth_src=src)

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
