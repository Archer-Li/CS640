import java.nio.ByteBuffer;
import java.util.Arrays;

public class Packet {
    private int seq;
    private int ack;
    private long timestamp;
    private int lengthNFlags;
    private int length;
    private int allZeros;
    private int checksum;
    private byte[] data;

    private int synFlag;
    private int finFlag;
    private int ackFlag;

    public Packet(int seq, int ack, byte[] data, int synFlag, int finFlag, int ackFlag) {
        this.seq = seq;
        this.ack = ack;
        this.timestamp = System.nanoTime();
        this.allZeros = 0;
        this.data = data;
        this.length = data.length;
        this.lengthNFlags = this.combineLengthNFlags();
        this.synFlag = synFlag;
        this.finFlag = finFlag;
        this.ackFlag = ackFlag;
    }

    public Packet(byte[] packet) {
        this.seq = this.seq(packet);
        this.ack = this.ack(packet);
        this.timestamp = this.timestamp(packet);
        this.length = this.length(packet);
        this.synFlag = this.SYNFlag(packet);
        this.finFlag = this.FINFlag(packet);
        this.ackFlag = this.ACKFlag(packet);
        this.allZeros = this.zeros(packet);
        this.checksum = this.checksum(packet);
        this.data = Arrays.copyOfRange(packet, 24, 24 + this.length);
        this.length = this.data.length;
    }

    public byte[] bytes() {
        var packet = ByteBuffer.allocate(24 + this.data.length);
        var seqSlice = ByteBuffer.allocate(4).putInt(this.seq).array();
        packet.put(seqSlice);
        var ackSlice = ByteBuffer.allocate(4).putInt(this.ack).array();
        packet.put(ackSlice);
        var timestampSlice = ByteBuffer.allocate(4).putLong(System.currentTimeMillis()).array();
        packet.put(timestampSlice);

        var lenSlice = ByteBuffer.allocate(4).putInt(this.combineLengthNFlags()).array();
        packet.put(lenSlice);
        var allZerosSlice = ByteBuffer.allocate(2).putInt(this.allZeros).array();
        packet.put(allZerosSlice);
        var checksumSlice = ByteBuffer.allocate(2).putInt(this.checksum).array();
        packet.put(checksumSlice);
        packet.put(this.data);
        return packet.array();
    }

    public int addChecksum(int checksum) {
        this.checksum = checksumHelper(checksum, this.checksum);
        return this.checksum;
    }

    private static int checksumHelper(int n1, int n2) {
        int sum = n1 + n2;
        String binarySum = Integer.toBinaryString(sum);
        if (binarySum.length() > 16) {
            return Integer.parseInt(binarySum.substring(binarySum.length() - 16)) + Integer.parseInt(binarySum.substring(0, binarySum.length() - 16));
        }
        return sum;
    }

    private int combineLengthNFlags() {
        int l = this.data.length << 3;
        if (this.ackFlag == 1) {
            l = l | 1;
        }
        if (this.finFlag == 1) {
            l = l | (1 << 2);
        }
        if (this.synFlag == 1) {
            l = l | (1 << 3);
        }
        return l;
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
    private int lenNFlag(byte[] packet) {
        return this.parsePacket(packet, 16, 20);
    }

    private int length(byte[] packet) {
        int lNFlag = this.lenNFlag(packet);
        return lNFlag >> 3;
    }

    private int flagBit(byte[] packet, int k) {
        int lNFlag = this.lenNFlag(packet);
        return (lNFlag >> k) & 1;
    }

    private int ACKFlag(byte[] packet) {
        return flagBit(packet, 0);
    }

    private int FINFlag(byte[] packet) {
        return flagBit(packet, 1);
    }

    private int SYNFlag(byte[] packet) {
        return flagBit(packet, 2);
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

    public int getLength() {
        return this.length;
    }

    public int getSeq() {
        return this.seq;
    }

    public int getAck() {
        return this.ack;
    }

    public int getFinFlag() {
        return this.finFlag;
    }

    public boolean notSimpleResponse() {
        return this.finFlag == 1 || this.synFlag == 1 || this.length > 0;
    }

    public boolean simpleResponse() {
        return !this.notSimpleResponse();
    }

    public boolean isAck() {
        return this.ackFlag == 1;
    }

    public boolean isFin() {
        return this.finFlag == 1;
    }

    public boolean isSyn() {
        return this.synFlag == 1;
    }

    public int getChecksum() {
        return this.checksum;
    }

    public int getZeros() {
        return this.allZeros;
    }

    public byte[] getData() {
        return this.data;
    }

    public void setSeq(int seq) {
        this.seq = seq;
    }

    public void setAck(int ack) {
        this.ack = ack;
    }

    public void setFinFlag(int finFlag) {
        this.finFlag = finFlag;
    }

    public void setSynFlag(int synFlag) {
        this.synFlag = synFlag;
    }

    public void setAckFlag(int ackFlag) {
        this.ackFlag = ackFlag;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

    public void setZeros(int zeros) {
        this.allZeros = zeros;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public void setChecksum(byte[] packet) {
        this.checksum = this.checksum(packet);
    }

    public void setZeros(byte[] packet) {
        this.allZeros = this.zeros(packet);
    }

    public void setLength(byte[] packet) {
        this.length = this.length(packet);
    }

    public void setSeq(byte[] packet) {
        this.seq = this.seq(packet);
    }

    public void setAck(byte[] packet) {
        this.ack = this.ack(packet);
    }

    @Override
    public String toString() {
        var sb = new StringBuilder();
        sb.append(this.timestamp).append(" ");
        if (this.synFlag == 1) {
            sb.append("S ");
        } else {
            sb.append("- ");
        }
        if (this.ackFlag == 1) {
            sb.append("A ");
        } else {
            sb.append("- ");
        }
        if (this.finFlag == 1) {
            sb.append("F ");
        } else {
            sb.append("- ");
        }
        if (this.length > 0) {
            sb.append("D ");
        } else {
            sb.append("- ");
        }
        sb.append(this.seq).append(" ");
        sb.append(this.length).append(" ");
        sb.append(this.ack);
        return sb.toString();
    }
}
