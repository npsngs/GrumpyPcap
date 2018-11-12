package com.grumpycat.pcap;

import android.annotation.SuppressLint;

/**
 * ＴＣＰ报头格式
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜               源端口号（ｓｏｕｒｃｅ　ｐｏｒｔ）           　｜       　目的端口号（ｄｅｓｔｉｎａｔｉｏｎ　ｐｏｒｔ）     ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜　　　　　　　　　　　　　　　　　　　　　　　　顺序号（ｓｅｑｕｅｎｃｅ　ｎｕｍｂｅｒ）　　　　　　　　　　　　　　　　　　　　　｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜　　　　　　　　　　　　　　　　　　　　　确认号（ａｃｋｎｏｗｌｅｄｇｅｍｅｎｔ　ｎｕｍｂｅｒ）　　　　　　　　　　　　　　　　　｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜　ＴＣＰ报头　　｜　　保　　            ｜Ｕ｜Ａ｜Ｐ｜Ｒ｜Ｓ｜Ｆ｜                                                     ｜
 * ｜　　　长度　　　｜　　留　　            ｜Ｒ｜Ｃ｜Ｓ｜Ｓ｜Ｙ｜Ｉ｜　　　　　　窗口大小（ｗｉｎｄｏｗ　ｓｉｚｅ 16位）              ｜
 * ｜　　（４位）   ｜　（６位）             ｜Ｇ｜Ｋ｜Ｈ｜Ｔ｜Ｎ｜Ｎ｜                                                     ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜              校验和（ｃｈｅｃｋｓｕｍ）                     ｜           紧急指针（ｕｒｇｅｎｔ　ｐｏｉｎｔｅｒ）       ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                                                选项＋填充（０或多个３２位字）                                    　｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                                                   数据（０或多个字节）                                            |
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 **/
public class TCPWrapper {
    public static final int FIN = 1;
    public static final int SYN = 2;
    public static final int RST = 4;
    public static final int PSH = 8;
    public static final int ACK = 16;
    public static final int URG = 32;

    private byte[] data;
    private int offset;
    public void withData(byte[] data, int offset){
        this.data = data;
        this.offset = offset;
    }

    public int getSrcPort(){
        return ByteUtils.readShort(data, offset) & 0xFFFF;
    }

    public int getDestPost(){
        return ByteUtils.readShort(data, offset+2) & 0xFFFF;
    }

    public int getSequenceNumber(){
        return ByteUtils.readInt(data, offset+4);
    }

    public int getAckNumber(){
        return ByteUtils.readInt(data, offset+8);
    }

    public int getHeaderLen(){
        return ((data[offset+12] & 0xFF) >> 4 )*4;
    }

    public byte getFlag(){
        return data[offset+13];
    }

    public int getWindowSize(){
        return ByteUtils.readShort(data, offset+14) & 0xFFFF;
    }

    public short getCheckSum(){
        return ByteUtils.readShort(data, offset+16) ;
    }

    public int getUrgentPointer(){
        return ByteUtils.readShort(data, offset+18) ;
    }

    public void setSrcPort(int port){
        ByteUtils.writeShort(data, offset, (short) port);
    }

    public void setDestPort(int port){
        ByteUtils.writeShort(data, offset+2, (short) port);
    }

    public void setCheckSum(short checkSum){
        ByteUtils.writeShort(data, offset+16, checkSum);
    }


    @SuppressLint("DefaultLocale")
    public String print() {
        return String.format("[Tcp %s%s%s%s%s%s Seq:%s AckId:%s]",
                (getFlag() & SYN) == SYN ? "SYN" : "",
                (getFlag() & ACK) == ACK ? "ACK" : "",
                (getFlag() & PSH) == PSH ? "PSH" : "",
                (getFlag() & RST) == RST ? "RST" : "",
                (getFlag() & FIN) == FIN ? "FIN" : "",
                (getFlag() & URG) == URG ? "URG" : "",
                getSequenceNumber(),
                getAckNumber());
    }
}
