import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class TCPSender {
    private DatagramSocket serverSocket;
    private int srcPort;
    private int destPort;

    private String destAddress;
    private int seq;
    private int nextAck;
    private int prevAck;

    public TCPSender(int srcPort, int destPort, String destAddress) {
        this.srcPort = srcPort;
        this.destPort = destPort;
        this.destAddress = destAddress;
        this.seq = 0;
        this.nextAck = 0;
        this.prevAck = 0;
        try {
            this.serverSocket = new DatagramSocket(srcPort);
        } catch (SocketException e) {
            System.out.println("SocketException: " + e.getMessage());
            System.exit(-1);
        }
    }

    // parse seq from packet
    private int seq(byte[] packet) {
        return this.parsePacket(packet, 0, 4);
    }

    // parse ack from packet
    private int ack(byte[] packet) {
        return this.parsePacket(packet, 4, 8);
    }

    // parse timestamp from packet
    private int timestamp(byte[] packet) {
        return this.parsePacket(packet, 8, 16);
    }

    // parse lenFlag from packet
    private int lenFlag(byte[] packet) {
        return this.parsePacket(packet, 16, 20);
    }

    // parse zeros from packet
    private int zeros(byte[] packet) {
        return this.parsePacket(packet, 20, 22);
    }

    // parse checksum from packet
    private int checksum(byte[] packet) {
        return this.parsePacket(packet, 22, 24);
    }

    private int parsePacket(byte[] packet, int l, int r) {
        var slice = Arrays.copyOfRange(packet, l, r);
        return ByteBuffer.wrap(slice).getInt();
    }

    private class Sender extends Thread {
        @Override
        public void run() {
            try {
                var data = new byte[24];
                var packet = new DatagramPacket(data, data.length);
                serverSocket.receive(packet);
                var ack = ack(packet.getData());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
    }

    private static class Receiver extends Thread {
        @Override
        public void run() {
            super.run();
        }
    }
}
