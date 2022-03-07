package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
    /**
     * Routing table for the router
     */
    private RouteTable routeTable;

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
            var oldCheckSum = header.getChecksum();
            header.resetChecksum();
            var bytes = header.serialize();

            // zeroed checksum
            header.deserialize(bytes, 0, bytes.length);


            if (header.getChecksum() != oldCheckSum) {
                return;
            }

            header.setTtl((byte) (header.getTtl() - 1));

            if (header.getTtl() == 0) {
                return;
            }

            header.resetChecksum();

            // drop packet if it is to router interfaces
            for (var face : interfaces.values()) {
                if (header.getDestinationAddress() == face.getIpAddress()) {
                    return;
                }
            }

            var routeEntry = this.routeTable.lookup(header.getDestinationAddress());
            if (routeEntry == null) {
                return;
            }

            if (routeEntry.getInterface() == inIface) {
                return;
            }

            var dest = routeEntry.getGatewayAddress() != 0 ? routeEntry.getGatewayAddress() : routeEntry.getDestinationAddress();

            var arpEntry = this.arpCache.lookup(dest);
            if (arpEntry == null) {
                return;
            }

            etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
            etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

            this.sendPacket(etherPacket, routeEntry.getInterface());
        }
    }
}
