package com.grumpycat.pcap;


import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Enumeration;

/**
 * Created by cc.he on 2018/8/29
 */
public class Utils{
    public static byte[] copyData(byte[] input, int offset, int size){
        if (input == null || offset < 0 || offset+size > input.length)
            throw new IllegalArgumentException();

        byte[] output = new byte[size];

        System.arraycopy(input, offset, output, 0, size);
        return output;
    }


    public static ByteBuffer copyByteBuffer(ByteBuffer buffer){
        int limit = buffer.limit();
        byte[] input = buffer.array();

        byte[] output = new byte[limit];
        System.arraycopy(input, buffer.arrayOffset(), output, 0, limit);

        return ByteBuffer.wrap(output);
    }

    public static byte[] copyData(ByteBuffer buffer){
        int limit = buffer.limit();
        byte[] input = buffer.array();

        byte[] output = new byte[limit];
        System.arraycopy(input, buffer.arrayOffset(), output, 0, limit);

        return output;
    }

    public static void copyValue(byte[] src, int srcOffset, byte[] dest, int destOffset, int len){
        for(int i =0; i<len; i++){
            dest[destOffset+i] = src[srcOffset+i];
        }
    }



    public static InetAddress ipIntToInet4Address(int ip) {
        byte[] ipAddress = new byte[4];
        ByteUtils.writeInt(ipAddress, 0, ip);
        try {
            return Inet4Address.getByAddress(ipAddress);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public static String ipIntToString(int ip) {
        return String.format("%s.%s.%s.%s", (ip >> 24) & 0x00FF,
                (ip >> 16) & 0x00FF, (ip >> 8) & 0x00FF, (ip & 0x00FF));
    }

    public static String ipBytesToString(byte[] ip) {
        return String.format("%s.%s.%s.%s", ip[0] & 0x00FF, ip[1] & 0x00FF, ip[2] & 0x00FF, ip[3] & 0x00FF);
    }

    public static int ipStringToInt(String ip) {
        String[] arrayStrings = ip.split("\\.");
        int r = (Integer.parseInt(arrayStrings[0]) << 24)
                | (Integer.parseInt(arrayStrings[1]) << 16)
                | (Integer.parseInt(arrayStrings[2]) << 8)
                | (Integer.parseInt(arrayStrings[3]));
        return r;
    }

    public static byte[] ipStringToByte(String ip) {
        String[] arrayStrings = ip.split("\\.");
        byte[] bytes = new byte[arrayStrings.length];

        bytes[0] = (byte) (Integer.parseInt(arrayStrings[0]) & 0xFF);
        bytes[1] = (byte) (Integer.parseInt(arrayStrings[1]) & 0xFF);
        bytes[2] = (byte) (Integer.parseInt(arrayStrings[2]) & 0xFF);
        bytes[3] = (byte) (Integer.parseInt(arrayStrings[3]) & 0xFF);
        return bytes;
    }

    private String toBinaryString(byte val){
        char[] buf = new char[8];
        int charPos = 8;
        do {
            buf[--charPos] = (val & 1) == 0?'0':'1';
            val >>>= 1;
        } while (charPos > 0);
        return new String(buf);
    }



    public static int getLocalIP(){
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()){
                NetworkInterface ntf = en.nextElement();
                Enumeration<InetAddress> enumIpAddr = ntf.getInetAddresses();

                while(enumIpAddr.hasMoreElements()){
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()
                            && (inetAddress instanceof Inet4Address)) {
                        byte[] rawAddress = inetAddress.getAddress();
                        int ip = ByteUtils.readInt(rawAddress, 0);
                        return ip;
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return 0;
    }

    public static void assertTrue(boolean value){
        if (!value)
            throw new IllegalStateException("AssertTrue failed");
    }
}
