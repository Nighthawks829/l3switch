sudo ovs-ofctl -O OpenFlow13 show s1
sudo ovs-ofctl -O OpenFlow13 dump-ports s1
sudo ovs-vsctl show
mininet> net
sudo ovs-ofctl -O OpenFlow13 dump-ports-desc s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo mn --controller=remote,ip=127.0.0.1 --mac -i 10.1.1.0/24 --switch=ovsk,protocols=OpenFlow13 --topo=single,2

46:55:ed:ea:71:cc
fe:fd:e8:6d:1a:45

sudo tcpdump -i s1-eth1 -w "$(date +%Y%m%d-%H%M%S).pcap"