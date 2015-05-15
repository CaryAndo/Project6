import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Random;

/**
 * CS380 Project 6: TCP Client
 *
 * @author Cary Anderson
 * */
public class TcpClient {

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("45.50.5.238", 38006);
            InputStream is = socket.getInputStream();
            int mySequenceNumber = new Random().nextInt(12)+1;
            sendTCP(socket, 0, mySequenceNumber, 0, false, true, false);
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

            byte seq1 = ar.get(4);
            byte seq2 = ar.get(5);
            byte seq3 = ar.get(6);
            byte seq4 = ar.get(7);

            int sequence = seq1<<24;
            sequence += (seq2<<16)&0xffffff;
            sequence += ((seq3<<8)&0xffff);
            sequence += (seq4&0xff);

            sendTCP(socket, 0, mySequenceNumber+1, sequence+1, true, false, false);
            readAndPrint(is);

            int finalMySequence = 0;
            int finalOtherSequence = 0;

            for (int i = 1; i < 13; i++) {
                int leNum = (int) Math.pow(2.0, (double) i);
                System.out.println(leNum);
                sendTCP(socket, leNum, mySequenceNumber + leNum, sequence + leNum, false, false, false);
                readAndPrint(is);
                finalMySequence = mySequenceNumber + leNum;
                finalOtherSequence = sequence + leNum;
            }

            System.out.println("Sending teardown:");
            sendTCP(socket, 0, finalMySequence + 1, finalOtherSequence + 1, false, false, true);
            readAndPrint(is);

        } catch (IOException ioe) {
            System.out.println("Socket threw an IO Error");
            ioe.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
            // "Just eat it, nah nah nah nah nah, just eat it." - Weird Al
        }
    }

    /**
     * Take an input stream and read four bytes as a hex string.
     *
     * @param is The input stream to read from
     * */
    private static void readAndPrint(InputStream is) {
        try {
            int a = is.read();
            int b = is.read();
            int c = is.read();
            int d = is.read();
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
     * @param ackNumber Acknowledgement number
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
        send[16] = (byte) 45; // (destination address)
        send[17] = (byte) 50; // (destination address)
        send[18] = (byte) 5; // (destination address)
        send[19] = (byte) 238; // (destination address)

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

        send[24] = (byte) (sequence>>24); // Sequence Number
        send[25] = (byte) ((sequence>>16)&0xff); // Sequence Number
        send[26] = (byte) ((sequence>>8)&0xff); // Sequence Number
        send[27] = (byte) (sequence & 0xff); // Sequence Number
        send[28] = (byte) ((ackNumber>>24)&0xff); // Acknowledgement Number
        send[29] = (byte) ((ackNumber>>16)&0xff); // Acknowledgement Number
        send[30] = (byte) ((ackNumber>>8)&0xff); // Acknowledgement Number
        send[31] = (byte) (ackNumber & 0xff); // Acknowledgement Number
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
        byte[] checksumArray = new byte[12 + 20 + len]; // 12 = pseudoheader, 20 = TCP Header
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
        checksumArray[16] = send[24]; // Sequence Number
        checksumArray[17] = send[25]; // Sequence Number
        checksumArray[18] = send[26]; // Sequence Number
        checksumArray[19] = send[27]; // Sequence Number
        checksumArray[20] = send[28]; // Acknowledgement Number
        checksumArray[21] = send[29]; // Acknowledgement Number
        checksumArray[22] = send[30]; // Acknowledgement Number
        checksumArray[23] = send[31]; // Acknowledgement Number
        checksumArray[24] = send[32]; // Offset
        checksumArray[25] = send[33]; // Control bits
        checksumArray[26] = send[34]; // Window
        checksumArray[27] = send[35]; // Window
        checksumArray[28] = send[36]; // checksum
        checksumArray[29] = send[37]; // checksum
        checksumArray[30] = send[38]; // Urgent Pointer
        checksumArray[31] = send[39]; // Urgent Pointer

        for (int i = 0; i < len; i++) {
            checksumArray[31+i] = 125;
        }

        short udpChecksum = calculateChecksum(checksumArray);
        byte rightCheck = (byte) (udpChecksum & 0xff);
        byte leftCheck = (byte) ((udpChecksum >> 8) & 0xff);

        send[36] = leftCheck; // Save checksum
        send[37] = rightCheck; // Save checksum

        for (int i = 0; i < len; i++) {
            send[i+40] = (byte) 125;
        }

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
     * @return The concatenated array
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
