import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Random;

public class TcpClient {

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("45.50.5.238", 38006);
            InputStream is = socket.getInputStream();

            sendTCP(socket, 0, new Random().nextInt(12)+1, 0,false, true, false);
            readAndPrint(is); // Response code

            ArrayList<Byte> ar = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                byte b = (byte) is.read();;

                ar.add(b);
                System.out.println(b);
            }

            byte[] arr = new byte[ar.size()];

            for (int i = 0; i < ar.size(); i++) {
                arr[i] = ar.get(i);
            }
            byte seq1 = arr[4];
            byte seq2 = arr[5];
            byte seq3 = arr[6];
            byte seq4 = arr[7];
            int sequence = (((((seq1<<8)+seq2)<<8)+seq3)<<8)+seq4; // As you can see, readability is important to me
            sequence += 1;


        } catch (IOException ioe) {
            ioe.printStackTrace();
        } catch (Exception e) {
            // "Just eat it, nah nah nah nah nah, just eat it." - Weird Al
        }
    }

    private static void readAndPrint(InputStream is) {
        try {
            int a = is.read();
            int b = is.read();
            int c = is.read();
            int d = is.read();
            System.out.print("Received: ");
            System.out.println("Received: 0x" + (Integer.toString(a, 16) + Integer.toString(b, 16) +
                            Integer.toString(c, 16) + Integer.toString(d, 16)).toUpperCase());
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Send a TCP packet
     *
     * @param sock Le socket to send le data
     * @param len Length of the data
     * @param sequence Sequence number
     * @param ack Set the ACK flag
     * @param syn Set the SYN flag
     * @param fin Set the FIN flag
     */
    private static void sendTCP(Socket sock, int len, int sequence, int ackNumber, boolean ack, boolean syn, boolean fin) {
        byte[] send = new byte[20 + 20 + len]; // 20 bytes for ip header + 20 bytes for TCP header

        send[0] = (byte) ((4 << 4) + 5); // Version 4 and 5 words
        send[1] = 0; // TOS (Don't implement)
        send[2] = 0; // Total length
        send[3] = (byte) (40 + len); // Total length (Computed later)
        send[4] = 0; // Identification (Don't implement)
        send[5] = 0; // Identification (Don't implement)
        send[6] = (byte) 0b01000000; // Flags and first part of Fragment offset
        send[7] = (byte) 0b00000000; // Fragment offset
        send[8] = 50; // TTL = 50
        send[9] = 0x06; // Protocol (TCP = 6)
        send[10] = 0; // CHECKSUM
        send[11] = 0; // CHECKSUM
        send[12] = (byte) 127; // 127.0.0.1 (source address)
        send[13] = (byte) 0; // 127.0.0.1 (source address)
        send[14] = (byte) 0; // 127.0.0.1 (source address)
        send[15] = (byte) 1; // 127.0.0.1 (source address)
        send[16] = (byte) 76; // (destination address)
        send[17] = (byte) 91; // (destination address)
        send[18] = (byte) 123; // (destination address)
        send[19] = (byte) 97; // (destination address)

        short length = (short) (20 + 20 + len); // Quackulate the total length (header lengths plus data length)
        byte right = (byte) (length & 0xff);
        byte left = (byte) ((length >> 8) & 0xff);
        send[2] = left;
        send[3] = right;

        short checksum = calculateChecksum(send); // Quackulate the checksum

        byte second = (byte) (checksum & 0xff);
        byte first = (byte) ((checksum >> 8) & 0xff);
        send[10] = first;
        send[11] = second;

        byte[] data = new byte[len];
        new Random().nextBytes(data); // Data = Random bytes

        /*
        * TCP Header
        * */
        send[20] = (byte) 12; // Source Port
        send[21] = (byte) 34; // Source Port
        send[22] = (byte) ((1234 >> 8) & 0xff); // Destination Port (Right Half)
        send[23] = (byte) (1234 & 0xff); // Destination Port (Left Half)

        send[24] = (byte) ((sequence & 0xff000000)>>24); // Sequence Number
        send[25] = (byte) ((sequence & 0x00ff0000)>>16); // Sequence Number
        send[26] = (byte) ((sequence & 0x0000ff00)>>8); // Sequence Number
        send[27] = (byte) (sequence & 0x000000ff); // Sequence Number
        send[28] = (byte) ((ackNumber & 0xff000000)>>24); // Acknowledgement Number
        send[29] = (byte) ((ackNumber & 0xff000000)>>16); // Acknowledgement Number
        send[30] = (byte) ((ackNumber & 0xff000000)>>8); // Acknowledgement Number
        send[31] = (byte) (ackNumber & 0xff000000); // Acknowledgement Number
        send[32] = 5 << 4; // Data Offset (5 32-bit words) + reserved + 1st bit of ECN (0)

        String controlBits = "000"; // 2 bits of ECN + URG

        if (ack) {
            controlBits += "1"; // ACK
        } else {
            controlBits += "0"; // ACK
        }

        controlBits += "00"; // PSH flag + RST flag

        if (syn) {
            controlBits += "1";
        } else {
            controlBits += 0;
        }

        if (fin) {
            controlBits += "1";
        } else {
            controlBits += "0";
        }

        send[33] = Byte.parseByte(controlBits, 2); // [end of] ECN + Control bits

        send[34] = 0; // Window
        send[35] = 0; // Window
        send[36] = 0; // Checksum
        send[37] = 0; // Checksum
        send[38] = 0; // Urgent Pointer
        send[39] = 0; // Urgent Pointer

        /*
        * pseudoheader + actual TCP header + data to calculate checksum
        * */
        byte[] checksumArray = new byte[12 + 20]; // 12 = pseudoheader, 20 = TCP Header
        checksumArray[0] = send[12]; // Source ip address
        checksumArray[1] = send[13]; // Source ip address
        checksumArray[2] = send[14]; // Source ip address
        checksumArray[3] = send[15]; // Source ip address
        checksumArray[4] = send[16]; // Destination ip address
        checksumArray[5] = send[17]; // Destination ip address
        checksumArray[6] = send[18]; // Destination ip address
        checksumArray[7] = send[19]; // Destination ip address
        checksumArray[8] = 0; // Zeros for days
        checksumArray[9] = send[9]; // Protocol

        int tcpLength = 20 + len; // Length of header + length of data

        checksumArray[10] = (byte) (tcpLength >> 8); // TCP length
        checksumArray[11] = (byte) tcpLength; // TCP length
        // end pseudoheader
        checksumArray[12] = send[20]; // Source Port
        checksumArray[13] = send[21]; // Source Port
        checksumArray[14] = send[22]; // Destination Port
        checksumArray[15] = send[23]; // Destination Port
        checksumArray[16] = send[24]; // Sequence
        checksumArray[17] = send[25]; // Sequence
        checksumArray[18] = send[26]; // Sequence
        checksumArray[19] = send[27]; // Sequence
        checksumArray[20] = send[28]; // Ack
        checksumArray[21] = send[29]; // Ack
        checksumArray[22] = send[30]; // Ack
        checksumArray[23] = send[31]; // Ack
        checksumArray[24] = send[32]; // Offset
        checksumArray[25] = send[33]; // Control bits
        checksumArray[26] = send[34]; // Window
        checksumArray[27] = send[35]; // Window
        checksumArray[28] = send[36]; // checksum
        checksumArray[29] = send[37]; // checksum
        checksumArray[30] = send[38]; // Urgent Pointer
        checksumArray[31] = send[39]; // Urgent Pointer
        // end actual header
        //checksumArray = concatenateByteArrays(checksumArray, data); // Append data

        short udpChecksum = calculateChecksum(checksumArray);
        byte rightCheck = (byte) (udpChecksum & 0xff);
        byte leftCheck = (byte) ((udpChecksum >> 8) & 0xff);

        send[36] = leftCheck; // Save checksum
        send[37] = rightCheck; // Save checksum

       /* for (int i = 40; i < send.length; i++) {
            send[i] = data[i-40];
        }*/

        for (int i = 0; i < len; i++) {
            send[i+40] = (byte) 125;
        }

        for (byte b : send) {
            System.out.println(b);
        }

        //send = concatenateByteArrays(send, data);

        try {
            OutputStream os = sock.getOutputStream();

            os.write(send);
            os.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Send the handshake packet
     * */
    private static void sendHandShake(Socket sock) {
        byte[] send = new byte[20+4];

        send[0] = (byte) ((4 << 4) + 5);; // Version 4 and 5 words
        send[1] = 0; // TOS (Don't implement)
        send[2] = 0; // Total length
        send[3] = 22; // Total length
        send[4] = 0; // Identification (Don't implement)
        send[5] = 0; // Identification (Don't implement)
        send[6] = (byte) 0b01000000; // Flags and first part of Fragment offset
        send[7] = (byte) 0b00000000; // Fragment offset
        send[8] = 50; // TTL = 50
        send[9] = 0x11; // Protocol (UDP = 17)
        send[10] = 0; // CHECKSUM
        send[11] = 0; // CHECKSUM
        send[12] = (byte) 127; // 127.0.0.1 (source address)
        send[13] = (byte) 0; // 127.0.0.1 (source address)
        send[14] = (byte) 0; // 127.0.0.1 (source address)
        send[15] = (byte) 1; // 127.0.0.1 (source address)
        send[16] = (byte) 0x2d; // 127.0.0.1 (destination address)
        send[17] = (byte) 0x32; // 127.0.0.1 (destination address)
        send[18] = (byte) 0x5; // 127.0.0.1 (destination address)
        send[19] = (byte) 0xee; // 127.0.0.1 (destination address)

        short length = (short) (20 + 4); // Quackulate the total length
        byte right = (byte) (length & 0xff);
        byte left = (byte) ((length >> 8) & 0xff);
        send[2] = left;
        send[3] = right;

        short checksum = calculateChecksum(send); // Quackulate the checksum

        byte second = (byte) (checksum & 0xff);
        byte first = (byte) ((checksum >> 8) & 0xff);
        send[10] = first;
        send[11] = second;

        send[20] = (byte) 0xDE;
        send[21] = (byte) 0xAD;
        send[22] = (byte) 0xBE;
        send[23] = (byte) 0xEF;

        try {
            OutputStream os = sock.getOutputStream();

            os.write(send);
            os.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Concatenate one array with another
     *
     * @param first First array
     * @param second Second array
     * */
    private static byte[] concatenateByteArrays(byte[] first, byte[] second) {
        int firstLength = first.length;
        int secondLength = second.length;

        byte[] ret = new byte[first.length + second.length];
        System.arraycopy(first, 0, ret, 0, first.length);
        System.arraycopy(second, 0, ret, first.length, second.length);

        return ret;
    }

    /**
     * Calculate internet checksum
     *
     * @param array Packet to compute the checksum
     * @return The checksum
     * */
    public static short calculateChecksum(byte[] array) {
        int length = array.length;
        int i = 0;

        int sum = 0;
        int data;

        // Count down
        while (length > 1) {
            data = (((array[i] << 8) & 0xFF00) | ((array[i + 1]) & 0xFF));
            sum += data;

            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }

            i = i + 2;
            length = length - 2;
        }

        if (length > 0) {
            sum += (array[i] << 8 & 0xFF00);
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0x0000FFFF;
                sum += 1;
            }
        }

        sum = ~sum;
        sum = sum & 0xFFFF;
        return (short) sum;
    }

}
