"""
L3Switch - A Layer 3 (IP Routing) OpenFlow Controller using Ryu Framework.

This controller acts as a software-defined router. It:
  - Learns host IP-to-MAC mappings via ARP
  - Responds to ARP requests on behalf of known hosts
  - Replies to ICMP (ping) requests directed at the switch's own interfaces
  - Routes IP packets between subnets using a dynamically-built route table
  - Installs proactive OpenFlow flow rules into OVS to speed up future packets

Typical topology:
    Host A (192.168.1.x) ── [s1-eth1] ── Switch ── [s1-eth2] ── Host B (192.168.2.x)

Usage:
    ryu-manager l3_switch.py
"""

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
    """
    A Ryu application that implements Layer 3 (IP) routing across OVS switches.

    Data structures maintained:
        mac_to_port  : {dpid: {mac_address: port_number}}
                       Used for L2 fallback — maps a host's MAC to the port it was seen on.

        ip_to_mac    : {dpid: {ip_address: mac_address}}
                       Maps known IP addresses to their MAC addresses (learned from ARP).
                       Also stores the switch's own interface IPs → MAC from OFPPortDescStats.

        port_to_ip   : {dpid: {port_number: ip_address}}
                       Maps each physical port number to the switch interface IP on that port.

        route_table  : {dpid: [ {network, netmask, prefixlen, port}, ... ]}
                       Static routes derived from the switch's own interface subnets.
                       Used to decide which port to send an IP packet out of.

        pending_routes : {dpid: set(ip_addresses)}
                         Tracks destination IPs that we have sent ARP requests for
                         but have not yet received a reply. Once the ARP reply arrives,
                         we install a flow rule for these IPs.
    """

    # Tell Ryu we want to speak OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        """Initialize the L3Switch application and all internal data structures."""
        super(L3Switch, self).__init__(*_args, **_kwargs)

        # L2: MAC address → port learning table  {dpid: {mac: port}}
        self.mac_to_port = {}

        # IP → MAC mapping learned from ARP traffic  {dpid: {ip: mac}}
        self.ip_to_mac = {}

        # Port number → switch interface IP  {dpid: {port: ip}}
        self.port_to_ip = {}

        # Routing table built from switch interface subnets  {dpid: [route_entry]}
        self.route_table = {}

    # -------------------------------------------------------------------------
    # Helper: Discover switch interface IPs from the OS
    # -------------------------------------------------------------------------
    def get_switch_ips(self, switch_name):
        """
        Query the Linux OS for IP addresses assigned to this switch's interfaces.

        Runs `ip -o -f inet addr show` and filters lines matching
        interfaces named like `<switch_name>-eth*` (e.g. s1-eth1, s1-eth2).

        Args:
            switch_name (str): The OVS bridge/switch name, e.g. "s1".

        Returns:
            dict: A dictionary keyed by interface name, each value being a dict with:
                  - "ip"        : The interface's IP address string (e.g. "192.168.1.1")
                  - "netmask"   : Subnet mask string (e.g. "255.255.255.0")
                  - "network"   : Network address string (e.g. "192.168.1.0")
                  - "prefixlen" : Prefix length as int (e.g. 24)

        Example return value:
            {
              "s1-eth1": {"ip": "192.168.1.1", "netmask": "255.255.255.0",
                          "network": "192.168.1.0", "prefixlen": 24},
              "s1-eth2": {"ip": "192.168.2.1", "netmask": "255.255.255.0",
                          "network": "192.168.2.0", "prefixlen": 24},
            }
        """

        ip_dict = {}

        # Run the Linux `ip` command to list all IPv4 addresses on all interfaces
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True,
            text=True,
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            iface = parts[1]  # e.g. "s1-eth1"

            # Only process interfaces belonging to this switch
            if not iface.startswith(f"{switch_name}-eth"):
                continue

            ip_prefix = parts[3]  # e.g. "192.168.1.1/24"
            ip_intf = ipaddress.IPv4Interface(ip_prefix)

            self.logger.info(ip_prefix)

            # Store structured address info for this interface
            ip_dict[iface] = {
                "ip": str(ip_intf.ip),
                "netmask": str(ip_intf.netmask),
                "network": str(ip_intf.network.network_address),
                "prefixlen": ip_intf.network.prefixlen,
            }

        return ip_dict

    # -------------------------------------------------------------------------
    # Event: Switch connects → build tables and install default flow
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle a new switch connection (OFPSwitchFeatures event).

        Triggered once when a switch first connects to this controller.
        Performs the following setup steps:
          1. Reads the switch's interface IPs from the OS.
          2. Builds the port_to_ip table (port number → interface IP).
          3. Builds the route_table (one entry per directly-connected subnet).
          4. Installs a table-miss flow rule to send all unknown packets to the controller.
          5. Requests detailed port information (MAC addresses) via OFPPortDescStatsRequest.

        Args:
            ev: The EventOFPSwitchFeatures event object from Ryu.
        """

        datapath = ev.msg.datapath  # The switch object (used to send OF messages)
        ofproto = datapath.ofproto  # OpenFlow protocol constants
        parser = datapath.ofproto_parser  # Factory for OF message objects
        dpid = datapath.id  # Unique switch ID (Datapath ID)

        self.logger.info("Switch %s connected", dpid)

        # Step 1: Discover this switch's interface IPs from the OS
        switch_ips = self.get_switch_ips(f"s{dpid}")
        self.logger.info("Switch %s IPs: %s", dpid, switch_ips)

        # Step 2: Build port_to_ip — maps port number to the IP on that port
        self.port_to_ip.setdefault(dpid, {})

        for iface, data in switch_ips.items():
            ip = data["ip"]

            # Extract the port number from the interface name (e.g. "s1-eth2" → 2)
            port_no = int(iface.split("eth")[1])

            self.port_to_ip[dpid][port_no] = ip

            self.logger.info("Mapped DPID=%s Port=%s -> IP=%s", dpid, port_no, ip)

        self.logger.info("Port to IP: %s", self.port_to_ip)

        # Step 3: Build route_table — one route per directly-connected subnet
        self.route_table.setdefault(dpid, [])

        for iface, data in switch_ips.items():
            network = data["network"]
            netmask = data["netmask"]
            prefixlen = data["prefixlen"]

            port_no = int(iface.split("eth")[1])

            # A route entry says: "to reach <network>, use <port_no>"
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

        # Step 4: Install a table-miss (catch-all) flow rule with priority 0.
        # Any packet not matched by a higher-priority rule will be sent to
        # this controller so we can handle it in software.
        match = parser.OFPMatch()  # Empty match = matches every packet
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

        # Step 5: Ask the switch to report its port details (name, MAC, speed, etc.)
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        self.logger.info("Sent OFPPortDescStatsRequest to switch dpid=%s", datapath.id)

    # -------------------------------------------------------------------------
    # Event: Switch replies with port descriptions → learn interface MACs
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
        Handle the OFPPortDescStatsReply event to learn each port's MAC address.

        After calling OFPPortDescStatsRequest in switch_features_handler,
        this reply gives us the hardware (MAC) address for each physical port.
        We store these in ip_to_mac so the switch can use its own interface
        MAC as the source MAC when sending ARP requests or ICMP replies.

        Args:
            ev: The EventOFPPortDescStatsReply event object from Ryu.
        """

        self.logger.info(ev.msg.body)
        datapath = ev.msg.datapath
        dpid = datapath.id

        # Ensure ip_to_mac is initialized for this switch
        if not hasattr(self, "ip_to_mac"):
            self.ip_to_mac = {}

        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info("---- Switch %s Port Information ----", dpid)
        for p in ev.msg.body:
            # Skip the LOCAL port (the switch's internal management port)
            if p.port_no == datapath.ofproto.OFPP_LOCAL:
                continue
            port_no = p.port_no
            name = p.name.decode("utf-8")  # Interface name, e.g. "s1-eth1"
            mac = p.hw_addr  # Hardware (MAC) address of this port
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

            # If we know the IP assigned to this port, record IP → MAC
            if dpid in self.port_to_ip and port_no in self.port_to_ip[dpid]:
                ip = self.port_to_ip[dpid][port_no]
                self.ip_to_mac[dpid][ip] = mac
                self.logger.info(
                    "Switch %s Port %s: IP=%s MAC=%s", dpid, port_no, ip, mac
                )

            self.logger.info(self.ip_to_mac)

    # -------------------------------------------------------------------------
    # Helper: Install a flow rule into the switch
    # -------------------------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Install an OpenFlow flow rule (FlowMod) into the switch's flow table.

        Once installed, the switch hardware will forward matching packets
        automatically — without sending them to the controller again.

        Args:
            datapath    : The switch object to send the FlowMod to.
            priority    : Rule priority (higher number = higher priority).
                          Table-miss rules use 0; L3 routing rules use 200.
            match       : OFPMatch object specifying which packets this rule matches.
            actions     : List of OFPAction objects describing what to do with matched packets.
            buffer_id   : (Optional) Buffer ID if the triggering packet is buffered in the switch.
                          Providing this causes the switch to also apply the rule to that packet.
        """

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Wrap actions in an APPLY_ACTIONS instruction
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            # Send FlowMod and also apply it to the buffered packet
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

    # -------------------------------------------------------------------------
    # Event: Packet arrives at the controller (table-miss or no matching rule)
    # -------------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle packets sent to the controller (PacketIn events).

        This is the main packet processing function. It handles three types of traffic:

          1. ARP Packets:
             - Learn the sender's IP→MAC mapping.
             - If we already know the target's MAC, send an ARP reply immediately.
             - After learning a new MAC, check if any pending L3 flows can now be installed.

          2. ICMP Echo Request (ping) to the switch's own interface IP:
             - Construct and send an ICMP Echo Reply back to the sender.
             - This allows hosts to ping the switch's own interface (e.g. gateway IP).

          3. IPv4 Packets (L3 routing):
             - Look up the destination IP in the route table to find the output port.
             - If the destination MAC is known, install a flow rule in OVS so future
               packets are forwarded in hardware without hitting the controller.
             - If the destination MAC is unknown, send an ARP request out the correct
               port and save the destination IP in pending_routes.

          4. L2 Fallback:
             - For non-IP, non-ARP Ethernet frames, fall back to basic MAC learning
               and flooding (standard L2 switch behaviour).

        Args:
            ev: The EventOFPPacketIn event object from Ryu.
        """

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]  # Port the packet arrived on
        dpid = datapath.id

        # Parse the raw packet bytes into protocol layers
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # Always present
        arp_pkt = pkt.get_protocol(arp.arp)  # None if not an ARP packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)  # None if not an IPv4 packet
        icmp_pkt = pkt.get_protocol(icmp.icmp)  # None if not an ICMP packet

        # ── ARP Handling ────────────────────────────────────────────────────
        if arp_pkt:
            # Step A: Learn the sender's IP→MAC mapping from any ARP packet
            self.ip_to_mac.setdefault(dpid, {})
            self.ip_to_mac[dpid][arp_pkt.src_ip] = arp_pkt.src_mac
            self.logger.info("Learned: IP=%s MAC=%s", arp_pkt.src_ip, arp_pkt.src_mac)

            if arp_pkt.opcode == arp.ARP_REQUEST:
                target_ip = arp_pkt.dst_ip

                # Step B: If we know the target's MAC, reply on its behalf (proxy ARP)
                if target_ip in self.ip_to_mac.get(dpid, {}):
                    mac_to_reply = self.ip_to_mac[dpid][target_ip]

                    # Build an ARP reply packet
                    arp_reply_pkt = packet.Packet()
                    arp_reply_pkt.add_protocol(
                        ethernet.ethernet(
                            ethertype=eth.ethertype,
                            dst=eth.src,  # Send back to the requester
                            src=mac_to_reply,  # Pretend to be the target
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

                    # Send the ARP reply out the port the request came in on
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

            # Step C: Now that we learned a MAC, try to install any pending L3 flows
            # that were waiting for this host's ARP reply
            self._try_install_l3_flow(datapath, dpid, arp_pkt.src_ip)
            return

        # ── ICMP Ping to Switch's Own Interface ─────────────────────────────
        if ip_pkt and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            dst_ip = ip_pkt.dst

            # Only reply if the destination IP belongs to one of our own interfaces
            if dst_ip in self.ip_to_mac.get(dpid, {}):
                src_mac = self.ip_to_mac[dpid][dst_ip]  # MAC of our interface

                # Build an ICMP Echo Reply packet
                icmp_reply = packet.Packet()
                icmp_reply.add_protocol(
                    ethernet.ethernet(
                        ethertype=eth.ethertype,
                        src=src_mac,  # Switch interface MAC as source
                        dst=eth.src,  # Reply to the host that pinged us
                    )
                )
                icmp_reply.add_protocol(
                    ipv4.ipv4(
                        dst=ip_pkt.src,  # Reply to the original sender
                        src=dst_ip,  # From our interface IP
                        proto=ip_pkt.proto,
                    )
                )
                icmp_reply.add_protocol(
                    icmp.icmp(
                        type_=icmp.ICMP_ECHO_REPLY,
                        code=0,
                        csum=0,  # Checksum is auto-calculated on serialize
                        data=icmp_pkt.data,  # Echo the same payload back
                    )
                )
                icmp_reply.serialize()

                # Send the ICMP reply back out the same port
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
                return

        # ── L3 IP Routing ────────────────────────────────────────────────────
        if ip_pkt:
            dst_ip = ip_pkt.dst

            # Step 1: Look up which port leads to the destination subnet
            out_port = None
            for route in self.route_table.get(dpid, []):
                network = ipaddress.IPv4Network(
                    f"{route['network']}/{route['prefixlen']}"
                )
                if ipaddress.IPv4Address(dst_ip) in network:
                    out_port = route["port"]
                    break

            if out_port is None:
                # No matching route — packet is unroutable, drop it
                self.logger.warning("No route found for %s", dst_ip)
                return

            # Step 2: Look up the destination host's MAC address
            dst_mac = self.ip_to_mac.get(dpid, {}).get(dst_ip)

            if dst_mac is None:
                # We don't know the destination MAC yet.
                # Send an ARP request to discover it, and remember this dst_ip
                # so we can install a flow rule once the ARP reply arrives.
                self.logger.info("Unknown MAC for %s, sending ARP request", dst_ip)

                # Save to pending_routes so _try_install_l3_flow can finish later
                self.pending_routes = getattr(self, "pending_routes", {})
                self.pending_routes.setdefault(dpid, set()).add(dst_ip)

                # Use our own port's IP and MAC as the ARP source
                src_ip = self.port_to_ip[dpid].get(out_port)
                src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip)

                if src_ip and src_mac:
                    # Build a broadcast ARP request asking "Who has <dst_ip>?"
                    arp_req = packet.Packet()
                    arp_req.add_protocol(
                        ethernet.ethernet(
                            ethertype=ether_types.ETH_TYPE_ARP,
                            dst="ff:ff:ff:ff:ff:ff",  # Broadcast
                            src=src_mac,
                        )
                    )
                    arp_req.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REQUEST,
                            src_mac=src_mac,
                            src_ip=src_ip,
                            dst_mac="00:00:00:00:00:00",  # Unknown target MAC
                            dst_ip=dst_ip,
                        )
                    )
                    arp_req.serialize()

                    # Send the ARP request out the correct port toward the destination
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

            # Step 3: We know the destination MAC.
            # Determine the correct source MAC (the switch interface facing the destination)
            src_ip_of_out_port = self.port_to_ip[dpid].get(out_port, "")
            new_src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip_of_out_port, eth.src)

            # Step 4: Install a flow rule in OVS so all future packets to this dst_ip
            # are forwarded in hardware (no controller involvement needed)
            match = parser.OFPMatch(
                eth_type=0x0800,  # Match IPv4 packets
                ipv4_dst=dst_ip,  # Match exact destination IP
            )

            actions = [
                parser.OFPActionSetField(eth_src=new_src_mac),  # Rewrite source MAC
                parser.OFPActionSetField(eth_dst=dst_mac),  # Rewrite destination MAC
                parser.OFPActionOutput(out_port),  # Forward out correct port
            ]

            # Priority 200 ensures this rule beats the table-miss rule (priority 0)
            self.add_flow(datapath, priority=200, match=match, actions=actions)
            self.logger.info(
                "Installed L3 flow: dst=%s -> port=%s src_mac=%s dst_mac=%s",
                dst_ip,
                out_port,
                new_src_mac,
                dst_mac,
            )

            # Step 5: Also forward the current (first) packet immediately,
            # since the flow rule only applies to future packets
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # ── L2 Fallback (non-IP, non-ARP Ethernet frames) ───────────────────
        # Drop LLDP (link-layer discovery) packets silently
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Learn which port this source MAC was seen on
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port

        # If we know which port the destination MAC is on, use it; otherwise flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD  # Send out all ports

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule for unicast forwarding (not for flooded packets)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # Packet is buffered in the switch — include buffer_id in FlowMod
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Forward the current packet (either unicast or flood)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data  # Include raw packet data only if not buffered

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # -------------------------------------------------------------------------
    # Helper: Install a pending L3 flow once we learn a host's MAC via ARP
    # -------------------------------------------------------------------------
    def _try_install_l3_flow(self, datapath, dpid, learned_ip):
        """
        Try to install a proactive L3 flow rule for a previously unknown destination.

        When we tried to route a packet to a host whose MAC was unknown,
        we sent an ARP request and stored the destination IP in `pending_routes`.
        This function is called every time a new IP→MAC mapping is learned (from
        an ARP reply). If the newly-learned IP was in our pending list, we now
        have all the information needed to install the flow rule.

        Args:
            datapath   : The switch object (used to send the FlowMod).
            dpid       : The switch's datapath ID.
            learned_ip : The IP address that was just learned from an ARP packet.
        """

        # Check if this IP was in our pending list
        pending = getattr(self, "pending_routes", {}).get(dpid, set())
        if learned_ip not in pending:
            return  # Nothing pending for this IP, nothing to dou

        parser = datapath.ofproto_parser

        # Find the output port for this IP using the route table
        out_port = None
        for route in self.route_table.get(dpid, []):
            network = ipaddress.IPv4Network(f"{route['network']}/{route['prefixlen']}")
            if ipaddress.IPv4Address(learned_ip) in network:
                out_port = route["port"]
                break

        if out_port is None:
            return  # No route found — cannot install flow

        # Retrieve the destination MAC we just learned
        dst_mac = self.ip_to_mac.get(dpid, {}).get(learned_ip)

        # Retrieve the source MAC for the switch's outgoing interface
        src_ip_of_out_port = self.port_to_ip[dpid].get(out_port, "")
        new_src_mac = self.ip_to_mac.get(dpid, {}).get(src_ip_of_out_port)

        if not dst_mac or not new_src_mac:
            return  # Still missing information — cannot install flow yet

        # Install the flow rule: match on dst IP, rewrite MACs, forward out port
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=learned_ip,
        )
        actions = [
            parser.OFPActionSetField(eth_src=new_src_mac),  # Use switch's outgoing MAC
            parser.OFPActionSetField(eth_dst=dst_mac),  # Use destination host's MAC
            parser.OFPActionOutput(out_port),
        ]
        self.add_flow(datapath, priority=200, match=match, actions=actions)
        self.logger.info(
            "Proactively installed L3 flow for %s -> port=%s dst_mac=%s",
            learned_ip,
            out_port,
            dst_mac,
        )

        # Remove from pending since the flow is now installed
        self.pending_routes[dpid].discard(learned_ip)
