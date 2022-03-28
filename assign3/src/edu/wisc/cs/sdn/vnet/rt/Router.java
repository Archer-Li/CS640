package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
    static class RipEntry {
        int metric;
        long timeStamp;

        RipEntry(int metric, long timeStamp) {
            this.metric = metric;
            this.timeStamp = timeStamp;
        }

        public void setMetric(int metric) {
            this.metric = metric;
        }

        public int getMetric() {
            return metric;
        }

        public long getTimeStamp() {
            return timeStamp;
        }

        public void setTimeStamp(long timeStamp) {
            this.timeStamp = timeStamp;
        }
    }

    static class RipKey {
        int ip;
        int mask;

        RipKey(int ip, int mask) {
            this.ip = ip;
            this.mask = mask;
        }

        public int hashCode() {
            return (ip + "/" + mask).hashCode();
        }

        public boolean equals(Object o) {
            if (o instanceof RipKey) {
                var k = (RipKey) o;
                return (this.ip == k.ip && this.mask == k.mask);
            }
            return false;
        }

        public String toString() {
            return ip + "/" + mask;
        }
    }

    private final static byte[] broadcastMac = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private Timer timer;

    /**
     * Routing table for the router
     */
    private final RouteTable routeTable;

    /**
     * Rip entry table
     */
    private final ConcurrentHashMap<RipKey, RipEntry> ripTable = new ConcurrentHashMap<>();
    ;

    /**
     * ARP cache for the router
     */
    private ArpCache arpCache;

    /**
     * Creates a router for a specific host.
     *
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.timer = new Timer();
    }

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable() {
        return this.routeTable;
    }

    /**
     * Load a new routing table from a file.
     *
     * @param routeTableFile the name of the file containing the routing table
     */
    public void loadRouteTable(String routeTableFile) {
        if (!routeTable.load(routeTableFile, this)) {
            System.err.println("Error setting up routing table from file "
                    + routeTableFile);
            System.exit(1);
        }

        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
    }

    /**
     * Load a new ARP cache from a file.
     *
     * @param arpCacheFile the name of the file containing the ARP cache
     */
    public void loadArpCache(String arpCacheFile) {
        if (!arpCache.load(arpCacheFile)) {
            System.err.println("Error setting up ARP cache from file "
                    + arpCacheFile);
            System.exit(1);
        }

        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     *
     * @param etherPacket the Ethernet packet that was received
     * @param inIface     the interface on which the packet was received
     */
    public void handlePacket(Ethernet etherPacket, Iface inIface) {
        System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

        if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
            // verify check sum
            var header = (IPv4) etherPacket.getPayload();
            if (header.getPayload() instanceof UDP && ((UDP) header.getPayload()).getDestinationPort() == UDP.RIP_PORT) {
                handleRIP(etherPacket, inIface);
                System.out.println("*** <- RIP packet handled");
                return;
            }

            var oldCheckSum = header.getChecksum();
            header.resetChecksum();
            var bytes = header.serialize();

            header.deserialize(bytes, 0, bytes.length);


            if (header.getChecksum() != oldCheckSum) {
                return;
            }

            header.setTtl((byte) (header.getTtl() - 1));

            if (header.getTtl() == 0) {
                this.sendICMP(etherPacket, inIface, (byte) 11, (byte) 0);
                return;
            }

            header.resetChecksum();

            for (var face : interfaces.values()) {
                if (header.getDestinationAddress() == face.getIpAddress()) {
                    var protocol = header.getProtocol();
                    if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
                        this.sendICMP(etherPacket, inIface, (byte) 3, (byte) 3);
                    }
                    if (protocol == IPv4.PROTOCOL_ICMP) {
                        var icmp = (ICMP) header.getPayload();
                        if (icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
                            sendEcho(etherPacket, inIface);
                        }
                    }
                    return;
                }
            }

            var routeEntry = this.routeTable.lookup(header.getDestinationAddress());
            // no matching route found
            if (routeEntry == null) {
                this.sendICMP(etherPacket, inIface, (byte) 3, (byte) 0);
                return;
            }

            if (routeEntry.getInterface() == inIface) {
                return;
            }

            var nextHop = routeEntry.getGatewayAddress() != 0 ? routeEntry.getGatewayAddress() : header.getDestinationAddress();

            var arpEntry = this.arpCache.lookup(nextHop);
            if (arpEntry == null) {
                this.sendICMP(etherPacket, inIface, (byte) 3, (byte) 1);
                return;
            }

            etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
            etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
            this.sendPacket(etherPacket, routeEntry.getInterface());
        }
    }

    private void sendICMP(Ethernet etherPacket, Iface outIface, byte type, byte code) {
        var ipv4 = (IPv4) etherPacket.getPayload();
        var packet = new Ethernet();
        packet.setSourceMACAddress(outIface.getMacAddress().toBytes());
        packet.setEtherType(Ethernet.TYPE_IPv4);

        var newIp = new IPv4();
        newIp.setTtl((byte) 64);
        newIp.setSourceAddress(outIface.getIpAddress());
        newIp.setDestinationAddress(ipv4.getSourceAddress());
        newIp.setProtocol(IPv4.PROTOCOL_ICMP);
        packet.setPayload(newIp);

        var icmp = new ICMP();
        icmp.setIcmpType(type);
        icmp.setIcmpCode(code);
        newIp.setPayload(icmp);

        var len = ipv4.getHeaderLength() * 4;
        var bytes = new byte[4 + len + 8];
        Arrays.fill(bytes, (byte) 0);
        var oriBytes = ipv4.serialize();
        System.arraycopy(oriBytes, 0, bytes, 4, len + 8);

        var data = new Data(bytes);

        icmp.setPayload(data);

        var mac = this.nextHop(ipv4.getSourceAddress());
        if (mac == null) {
            return;
        }

        packet.setDestinationMACAddress(mac.toBytes());
        this.sendPacket(packet, outIface);
    }

    private MACAddress nextHop(int destAddr) {
        var routeEntry = this.routeTable.lookup(destAddr);
        if (routeEntry == null) {
            return null;
        }
        var nextHop = routeEntry.getGatewayAddress() != 0 ? routeEntry.getGatewayAddress() : destAddr;
        var arpEntry = this.arpCache.lookup(nextHop);
        if (arpEntry == null) {
            return null;
        }
        return arpEntry.getMac();
    }

    private void sendEcho(Ethernet etherPacket, Iface outIface) {
        var ipv4 = (IPv4) etherPacket.getPayload();
        var packet = new Ethernet();
        packet.setSourceMACAddress(outIface.getMacAddress().toBytes());
        packet.setEtherType(Ethernet.TYPE_IPv4);

        var newIp = new IPv4();
        newIp.setTtl((byte) 64);
        newIp.setProtocol(IPv4.PROTOCOL_ICMP);
        newIp.setSourceAddress(ipv4.getDestinationAddress());
        newIp.setDestinationAddress(ipv4.getSourceAddress());

        var icmp = new ICMP();
        icmp.setIcmpType((byte) 0);
        icmp.setIcmpCode((byte) 0);

        var data = new Data(ipv4.getPayload().getPayload().serialize());

        packet.setPayload(newIp);
        newIp.setPayload(icmp);
        icmp.setPayload(data);

        var destMac = this.nextHop(ipv4.getSourceAddress());

        if (destMac == null) {
            return;
        }

        packet.setDestinationMACAddress(destMac.toBytes());
        this.sendPacket(packet, outIface);

    }

    private Boolean hasDestAddress(Ethernet etherPacket) {
        var destAddr = etherPacket.getDestinationMAC();
        for (var face : interfaces.values()) {
            if (face.getMacAddress().equals(destAddr)) {
                return true;
            }
        }
        return false;
    }

    // handle RIP packet
    private void handleRIP(Ethernet etherPacket, Iface inIface) {
        var ip = (IPv4) etherPacket.getPayload();
        var udp = (UDP) ip.getPayload();
        var rip = (RIPv2) udp.getPayload();

        if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
            this.sendRIP(inIface, ip.getSourceAddress(), etherPacket.getSourceMACAddress(), RIPv2.COMMAND_RESPONSE);
            System.out.println("RIPv2 request received from " + IPv4.fromIPv4Address(ip.getSourceAddress()) + " to " + IPv4.fromIPv4Address(ip.getDestinationAddress()));
        }
        if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
            System.out.println("RIPv2 response received from " + IPv4.fromIPv4Address(ip.getSourceAddress()) + " to " + IPv4.fromIPv4Address(ip.getDestinationAddress()));
            boolean isChanged = false;
            for (var entry : rip.getEntries()) {
                var key = new RipKey(entry.getAddress(), entry.getSubnetMask());
                var metric = Integer.max(entry.getMetric() + 1, 16);
                var ripEntry = this.ripTable.get(key);
                if (ripEntry != null) {
                    ripEntry.setTimeStamp(System.currentTimeMillis());
                }
                if (ripEntry == null || metric < ripEntry.getMetric()) {
                    this.ripTable.put(key, new RipEntry(metric, System.currentTimeMillis()));
                    if (this.routeTable.lookup(entry.getAddress() & entry.getSubnetMask()) != null) {
                        routeTable.remove(entry.getAddress(), entry.getSubnetMask());
                    }
                    System.out.println("insert to route table: " + entry.getAddress() + "/" + entry.getSubnetMask() + " " + metric);
                    routeTable.insert(entry.getAddress(), entry.getNextHopAddress(), entry.getSubnetMask(), inIface);
                    isChanged = true;
                }
            }
            if (isChanged) {
                this.sendUnsolicitedResponse();
                System.out.println("Routing table changed");
            }
        }
    }

    private void sendRIP(Iface inIface, int destIp, byte[] destAddr, byte command) {
        var rip = this.newRipPacket(inIface, destIp, destAddr, command);
        this.sendPacket(rip, inIface);
    }

    // send RIP packet to interfaces and update riptable
    public void runRip() {
        for (var face : interfaces.values()) {
            int mask = face.getSubnetMask();
            int ip = face.getIpAddress() & mask;
            this.routeTable.insert(ip, 0, mask, face);
            this.ripTable.put(new RipKey(ip, mask), new RipEntry(0, 0));
            this.sendRIP(face, IPv4.toIPv4Address("240.0.0.9"), Router.broadcastMac, RIPv2.COMMAND_REQUEST);
        }
        this.timer.schedule(new SendUnsolicitedResponse(), 0, 10 * 1000);
        this.timer.schedule(new RemoveOutdatedRip(), 0, 30 * 1000);
    }

    private void sendUnsolicitedResponse() {
        for (var face : interfaces.values()) {
            this.sendRIP(face, IPv4.toIPv4Address("240.0.0.9"), Router.broadcastMac, RIPv2.COMMAND_RESPONSE);
        }
    }

    private Ethernet newRipPacket(Iface inIface, int destIP, byte[] destMac, byte command) {
        var ether = new Ethernet();
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setDestinationMACAddress(destMac);

        var udp = new UDP();
        udp.setDestinationPort(UDP.RIP_PORT);
        udp.setSourcePort(UDP.RIP_PORT);

        var newIp = new IPv4();
        newIp.setTtl((byte) 64);
        newIp.setProtocol(IPv4.PROTOCOL_UDP);
        newIp.setSourceAddress(inIface.getIpAddress());
        newIp.setDestinationAddress(destIP);

        var rip = new RIPv2();
        rip.setCommand(command);
        if (command == RIPv2.COMMAND_RESPONSE) {
            synchronized (this.routeTable) {
                for (var entry : this.routeTable.getEntries()) {
                    var ripV2 = new RIPv2Entry();
                    ripV2.setAddress(entry.getDestinationAddress());
                    var key = new RipKey(entry.getDestinationAddress(), entry.getMaskAddress());
                    ripV2.setMetric(ripTable.get(key).getMetric());
                    ripV2.setSubnetMask(entry.getMaskAddress());
                    ripV2.setNextHopAddress(inIface.getIpAddress());
                    rip.addEntry(ripV2);
                }
            }
        }

        udp.setPayload(rip);
        newIp.setPayload(udp);
        ether.setPayload(newIp);

        return ether;
    }

    class SendUnsolicitedResponse extends TimerTask {
        @Override
        public void run() {
            sendUnsolicitedResponse();
        }
    }

    class RemoveOutdatedRip extends TimerTask {
        @Override
        public void run() {
            var currentTime = System.currentTimeMillis();
            synchronized (ripTable) {
                boolean isChanged = false;
                var iter = ripTable.entrySet().iterator();
                while (iter.hasNext()) {
                    var entry = iter.next();
                    if (entry.getValue().getTimeStamp() != 0 && currentTime - entry.getValue().getTimeStamp() >= 30 * 1000) {
                        routeTable.remove(entry.getKey().ip, entry.getKey().mask);
                        iter.remove();
                        isChanged = true;
                    }
                }
                if (isChanged) {
                    sendUnsolicitedResponse();
                }
            }
        }
    }
}
