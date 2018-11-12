package com.grumpycat.pcap;

/**
 * Created by cc.he on 2018/9/28
 */
public class HexStr{
    private static final char[] HEX_CHAR = {
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'a', 'b',
            'c', 'd', 'e', 'f'};

    public static String byte2Hex(byte b) {
        char[] buf = new char[2];
        buf[0] = HEX_CHAR[b >>> 4 & 0xf];
        buf[1] = HEX_CHAR[b & 0xf];
        return new String(buf);
    }

    public static String bytes2Hex(byte[] data, int offset, int len){
        String s = "";
        int index = offset;
        int row = 0;
        while (index < len){
            s += HexStr.byte2Hex(data[index]);
            index++;
            row++;
            if (row > 15){
                s += "\n";
                row = 0;
            }
        }
        return s;
    }
}
