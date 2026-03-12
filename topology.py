from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from time import sleep


class SingleLayer3SwitchTopo(Topo):
    "Single Layer 3 Switch connected to 2 hosts"

    def build(self):
        s1 = self.addSwitch("s1")
        h1 = self.addHost("h1",mac="00:00:00:00:11:11",ip="192.168.1.10/24",defaultRoute="via 192.168.1.1")
        h2 = self.addHost("h2",mac="00:00:00:00:22:22",ip="192.168.2.10/24",defaultRoute="via 192.168.2.1")

        self.addLink(h1, s1)
        self.addLink(h2, s1)


if __name__ == "__main__":
    setLogLevel("info")
    topo = SingleLayer3SwitchTopo()
    c1 = RemoteController("c1", ip="127.0.0.1")
    net = Mininet(topo=topo, controller=c1)
    net.start()

    print("\n** Configuring Switch Port IP")
    s1=net.get("s1")
    s1.cmd("ifconfig s1-eth1 192.168.1.1 netmask 255.255.255.0")
    s1.cmd("ifconfig s1-eth2 192.168.2.1 netmask 255.255.255.0")

    CLI(net)
    net.stop()
