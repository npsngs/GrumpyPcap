package com.grumpycat.pcap;

import android.annotation.SuppressLint;

/**
 * UDP数据报格式
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜  １６位源端口号         ｜   １６位目的端口号        ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜  １６位ＵＤＰ长度       ｜   １６位ＵＤＰ检验和       ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                  数据（如果有）                    ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 **/
public class UDPWrapper {
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

    public int getLen(){
        return ByteUtils.readShort(data, offset+4) ;
    }

    public short getCheckSum(){
        return ByteUtils.readShort(data, offset+6) ;
    }

    public void setCheckSum(short checkSum){
        ByteUtils.writeShort(data, offset+6, checkSum);
    }


    public void setSrcPort(int port){
        ByteUtils.writeShort(data, offset, (short) port);
    }

    public void setDestPort(int port){
        ByteUtils.writeShort(data, offset+2, (short) port);
    }

    public void setLen(int len){
        ByteUtils.writeShort(data, offset + 4, (short) len);
    }

    @SuppressLint("DefaultLocale")
    public String print() {
        return String.format("\tsrcPort:%d\tdestPort:%d\n", getSrcPort(), getDestPost());
    }
}
