package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device implements Runnable {
    class Entry {
        private MACAddress mac;
        private Iface iface;
        private long time;

        public Entry(MACAddress mac, Iface iface) {
            this.mac = mac;
            this.iface = iface;
            this.time = System.currentTimeMillis();
        }

        public void setIface(Iface iface) {
            this.iface = iface;
        }

        public void setMac(MACAddress mac) {
            this.mac = mac;
        }

        public Iface getIface() {
            return iface;
        }

        public MACAddress getMac() {
            return mac;
        }

        public void setTime(long time) {
            this.time = time;
        }

        public long getTime() {
            return time;
        }
    }

    private final ConcurrentHashMap<MACAddress, Entry> switchTable;

    /**
     * Creates a router for a specific host.
     *
     * @param host hostname for the router
     */
    public Switch(String host, DumpFile logfile) {
        super(host, logfile);
        this.switchTable = new ConcurrentHashMap<>();
        var thread = new Thread(this);
        thread.start();
    }

    public void run() {
        try {
            while (true) {
                if (this.switchTable != null) {
                    for (var entry : this.switchTable.entrySet()) {
                        if (this.timeOut(entry.getValue().getTime())) {
                            this.switchTable.remove(entry.getKey());
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private boolean timeOut(long begin) {
        return System.currentTimeMillis() - begin >= 10000L;
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     *
     * @param etherPacket the Ethernet packet that was received
     * @param inIface     the interface on which the packet was received
     */
    public void handlePacket(Ethernet etherPacket, Iface inIface) {
        System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));
        var srcMac = etherPacket.getSourceMAC();
        var destMac = etherPacket.getDestinationMAC();

        if (this.switchTable.containsKey(destMac)) {
            var entry = this.switchTable.get(destMac);
            // if it's time out, remove it, otherwise send packet
            if (this.timeOut(entry.getTime())) {
                this.switchTable.remove(destMac);
            } else {
                sendPacket(etherPacket, entry.getIface());
            }
        }

        if (!this.switchTable.containsKey(destMac)) {
            broadcast(etherPacket, inIface);
        }

        // update source mac entry
        if (this.switchTable.containsKey(srcMac)) {
            var entry = this.switchTable.get(srcMac);
            entry.setIface(inIface);
            entry.setTime(System.currentTimeMillis());
        } else {
            this.switchTable.put(srcMac, new Entry(srcMac, inIface));
        }

    }

    private void broadcast(Ethernet etherPacket, Iface inIface) {
        // out mac not found, have to broadcast
        for (var face : this.interfaces.values()) {
            if (!face.equals(inIface)) {
                sendPacket(etherPacket, face);
            }
        }
    }
}
