import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

public class Iperfer {
    private static final int DATA_SIZE = 1024;
    private static final String ARG_ERROR = "Error: missing or additional arguments";
    private static final String PORT_ERROR = "Error: port number must be in the range 1024 to 65535";

    static class Client {
        private final int port;
        private final String host;
        private final long time;

        public Client(String host, int port, long time) {
            this.port = port;
            this.host = host;
            this.time = time * 1000;
        }

        public float send() throws IOException {
            var socket = new Socket(this.host, this.port);
            // create a data with 1
            var data = this.data(1);
            var outputStream = socket.getOutputStream();
            var dataOutputStream = new DataOutputStream(outputStream);
            var startTime = System.currentTimeMillis();
            var currTime = System.currentTimeMillis();
            int totalSend = 0;
            while (currTime - startTime < this.time) {
                // send data out
                dataOutputStream.write(data);
                dataOutputStream.flush();
                currTime = System.currentTimeMillis();
                totalSend += data.length;
            }
            dataOutputStream.close();

            var duration = System.currentTimeMillis() - startTime;
            var rate = speed(totalSend, duration);
            summary(totalSend, rate);
            return rate;
        }

        private byte[] data(int value) {
            return ByteBuffer.allocate(DATA_SIZE).putInt(value).array();
        }

        private void summary(int send, float rate) {
            System.out.println("sent=" + send / 1000.0 + " KB rate=" + 8 * rate / 1000.0 + " Mbps");
        }
    }

    static class Server {
        private final ServerSocket server;

        public Server(int port) throws IOException {
            this.server = new ServerSocket(port);
        }

        public float listen() throws IOException {
            var socket = this.server.accept();
            var startTime = System.currentTimeMillis();

            var in = socket.getInputStream();
            var data = new byte[DATA_SIZE];
            int received = 0;
            while (in.read() < 0) {
                in.read(data);
                received += data.length;
            }
            var duration = startTime - System.currentTimeMillis();
            var rate = speed(received, duration);
            summary(received, rate);
            return rate;
        }

        private void summary(int received, float rate) {
            System.out.println("received=" + received / 1000.0 + " KB rate=" + 8 * rate / 1000.0 + " Mbps");
        }
    }


    private static float speed(int size, long time) {
        return (float) (size / time);
    }

    private static boolean checkPort(int port) {
        return port >= 1024 && port <= 65535;
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println(ARG_ERROR);
        }
        var mode = args[0];
        if ("-c".equals(mode)) {
            if (args.length != 7 || !"-h".equals(args[1]) || !"-p".equals(args[3]) || !"-t".equals(args[5])) {
                System.out.println(ARG_ERROR);
                return;
            }
            var host = args[2];
            int port = Integer.parseInt(args[4]);
            if (!checkPort(port)) {
                System.out.println(PORT_ERROR);
                return;
            }
            long time = Long.parseLong(args[6]);
            var client = new Client(host, port, time);
            client.send();
        }
        if ("-s".equals(mode)) {
            if (args.length != 3 || !"-p".equals(args[2])) {
                System.out.println(ARG_ERROR);
                return;
            }
            int port = Integer.parseInt(args[2]);
            if (!checkPort(port)) {
                System.out.println(PORT_ERROR);
                return;
            }
            var server = new Server(port);
            server.listen();
        }
    }
}
