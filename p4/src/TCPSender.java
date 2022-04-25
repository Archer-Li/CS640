import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Semaphore;

public class TCPSender {
    private final int MTU = 1500;
    private String fileName;
    private int windowSize;
    private int mtu;
    private DatagramSocket serverSocket;
    private int srcPort;
    private int destPort;

    private String destAddress;
    private int seq;
    private int nextSeq;
    private int nextAck;
    private int prevAck;
    private Semaphore mutex;

    private boolean finished;

    private int payloadSize;

    private final int HEADERSIZE = 24;

    public TCPSender(int srcPort, int destPort, String destAddress, String fileName) {
        this.srcPort = srcPort;
        this.destPort = destPort;
        this.destAddress = destAddress;
        this.seq = 0;
        this.nextAck = 0;
        this.prevAck = 0;
        this.nextSeq = 0;
        this.mutex = new Semaphore(1);
        this.finished = false;
        this.fileName = fileName;
        this.payloadSize = MTU - HEADERSIZE;

        try {
            this.serverSocket = new DatagramSocket(srcPort);
        } catch (SocketException e) {
            System.out.println("SocketException: " + e.getMessage());
            System.exit(-1);
        }


        // begin handshake
        this.handshake();

    }

    private void handshake() {
        try {
            this.mutex.acquire();
            var packet = new Packet(this.nextSeq, this.nextAck, new byte[0], 1, 0, 0);
            this.sendPacket(packet);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        } finally {
            this.mutex.release();
        }
    }

    private void updateSend(Packet packet) {
        // do not update if packet is a simple response i.e. ack only
        if (packet.simpleResponse()) {
            return;
        }
        this.seq = this.nextSeq;
        if (packet.getLength() > 0) {
            this.nextSeq = this.nextSeq + packet.getLength();
        } else {
            this.nextSeq = this.nextSeq + 1;
        }
    }

    private void updateReceive(Packet packet) {

        if (packet.getLength() > 0) {
            this.nextAck = packet.getSeq() + packet.getLength();
        } else {
            this.nextAck = packet.getSeq() + 1;
        }

    }

    private void sendPacket(Packet packet) throws IOException {
        var bytes = packet.bytes();
        var data = new DatagramPacket(bytes, bytes.length, InetAddress.getByName(this.destAddress), this.destPort);
        this.serverSocket.send(data);
        this.updateSend(packet);
        System.out.println("snd " + packet);
    }

    private Packet receivePacket() throws IOException {
        var data = new byte[24];
        var datagramPacket = new DatagramPacket(data, data.length);
        serverSocket.receive(datagramPacket);

        var packet = new Packet(datagramPacket.getData());
        System.out.println("rcv " + packet);
        return packet;
    }

    private class Receiver extends Thread {
        private boolean checkAck(Packet packet) {
            if (packet.getAck() != nextSeq) {
                return false;
            }
            if (packet.notSimpleResponse()) {
                return packet.getSeq() == nextAck;
            }
            return true;
        }

        @Override
        public void run() {
            try {
                var packet = receivePacket();
                if (checkAck(packet)) {
                    if (packet.notSimpleResponse()) {
                        updateReceive(packet);
                        // response
                        var ackPacket = new Packet(seq, nextAck, new byte[0], 0, 0, 1);
                        sendPacket(ackPacket);

                    } else { // get ack packet from receiver
                        prevAck = packet.getAck() - 1;
                        // send finish packet
                        if (finished) {
                            var finishPacket = new Packet(nextSeq, nextAck, new byte[0], 0, 1, 0);
                            sendPacket(finishPacket);
                        }
                    }
                } else {
                    // response
                }
            } catch (
                    IOException e) {
                throw new RuntimeException(e);
            }

        }
    }

    private class Sender extends Thread {
        private FileInputStream file;

        public Sender() {
            try {
                this.file = new FileInputStream(fileName);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }

        int curOffset = 0; //current position in the file


        @Override
        public void run() {
            try {
                while (!finished) {
                    // enough window to send data
                    if (payloadSize + nextSeq < windowSize + prevAck + 1) {
                        mutex.acquire();
                        var bytes = new byte[payloadSize];
                        var length = this.file.read(bytes, 0, payloadSize);

                        Packet dataPacket;
                        if (length <= 0) {
                            finished = true;
                            dataPacket = new Packet(seq, nextAck, new byte[0], 0, 0, 0);
                        } else {
                            dataPacket = new Packet(seq, nextAck, bytes, 0, 0, 0);
                        }
                        sendPacket(dataPacket);
                        updateSend(dataPacket);
                        mutex.release();
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }
    }
}
