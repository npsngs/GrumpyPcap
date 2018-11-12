package com.grumpycat.pcap;

import android.annotation.SuppressLint;

/**
 * IP报文格式
 * 0                                   　　　　       15  16　　　　　　　　　　　　　　　　　　　　　　　　   31
 * ｜　－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜  ４　位     ｜   ４位首     ｜      ８位服务类型      ｜      　　         １６位总长度            　   ｜
 * ｜  版本号     ｜   部长度     ｜      （ＴＯＳ）　      ｜      　 　 （ｔｏｔａｌ　ｌｅｎｇｔｈ）    　    ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜  　　　　　　　　１６位标识符                         ｜　３位    ｜　　　　１３位片偏移                 ｜
 * ｜            （ｉｎｄｅｎｔｉｆｉｅｒ）                 ｜　标志    ｜      （ｏｆｆｓｅｔ）　　           ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜      ８位生存时间ＴＴＬ      ｜       ８位协议        ｜　　　　　　　　１６位首部校验和                  ｜
 * ｜（ｔｉｍｅ　ｔｏ　ｌｉｖｅ）　　｜   （ｐｒｏｔｏｃｏｌ） ｜              （ｃｈｅｃｋｓｕｍ）               ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                              ３２位源ＩＰ地址（ｓｏｕｒｃｅ　ａｄｄｒｅｓｓ）                           ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                         ３２位目的ＩＰ地址（ｄｅｓｔｉｎａｔｉｏｎ　ａｄｄｒｅｓｓ）                     ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                                          ３２位选项（若有）                                        ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 * ｜                                                                                                  ｜
 * ｜                                               数据                                               ｜
 * ｜                                                                                                  ｜
 * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
 **/

public class IPWrapper {
    private TCPWrapper tcpWrapper = new TCPWrapper();
    private UDPWrapper udpWrapper = new UDPWrapper();

    private byte[] data;
    private int offset;
    public void withData(byte[] data, int offset){
        this.data = data;
        this.offset = offset;
    }

    public void withData(byte[] data){
        withData(data, 0);
    }

    public byte[] getData() {
        return data;
    }


    public int getOffset(){
        return offset;
    }


    public int getVersion(){
        return data[offset] >>> 4;
    }

    public int getHeaderLen(){
        return (data[offset] & 0x0F) * 4;
    }

    public byte getTOS(){
        return data[offset+1];
    }

    public int getTotalLen(){
        return ByteUtils.readShort(data, offset + 2) & 0xFFFF;
    }

    public int getIdentifier(){
        return ByteUtils.readShort(data, offset + 4) & 0xFFFF;
    }

    public int getFlag(){
        return data[offset + 6] >>> 5;
    }

    public int getBitOffset(){
        return ByteUtils.readShort(data, offset + 6) & 0x1FFF;
    }

    public int getTTL(){
        return data[offset + 8];
    }

    public byte getProtocol(){
        return data[offset + 9];
    }

    public short getCheckSum(){
        return ByteUtils.readShort(data, offset + 10);
    }

    public int getSrcAddress(){
        return ByteUtils.readInt(data, offset + 12);
    }

    public int getDestAddress(){
        return ByteUtils.readInt(data, offset + 16);
    }

    public int getDataLen(){
        return getTotalLen() - getHeaderLen();
    }

    public TCPWrapper getTCPWrapper() {
        tcpWrapper.withData(data, getHeaderLen());
        return tcpWrapper;
    }

    public UDPWrapper getUDPWrapper() {
        udpWrapper.withData(data, getHeaderLen());
        return udpWrapper;
    }

    public void setSrcAddress(int address){
        ByteUtils.writeInt(data, offset + 12, address);
    }

    public void setDestAddress(int address){
        ByteUtils.writeInt(data, offset + 16, address);
    }

    public void setCheckSum(short checkSum){
        ByteUtils.writeShort(data, offset + 10, checkSum);
    }

    public void setTotalLen(int totalLen){
        ByteUtils.writeShort(data, offset + 2, (short) totalLen);
    }

    public boolean computeIPCheckSum() {
        short oldCheckSum = getCheckSum();
        setCheckSum((short) 0);
        short newCheckSum = ByteUtils.checksum(0, data, offset, getHeaderLen());
        setCheckSum(newCheckSum);
        return oldCheckSum == newCheckSum;
    }


    public boolean computeTCPCheckSum() {
        int headerLen = getHeaderLen();
        tcpWrapper.withData(data, getHeaderLen());

        short oldCheckSum = tcpWrapper.getCheckSum();
        tcpWrapper.setCheckSum((short) 0);
        long sum = computePseudoHeaderSum();
        short newCheckSum = ByteUtils.checksum(sum, data, headerLen, getDataLen());
        tcpWrapper.setCheckSum(newCheckSum);
        return oldCheckSum == newCheckSum;
    }

    public boolean computeUDPCheckSum() {
        int headerLen = getHeaderLen();
        udpWrapper.withData(data, getHeaderLen());

        short oldCheckSum = udpWrapper.getCheckSum();
        udpWrapper.setCheckSum((short) 0);
        long sum = computePseudoHeaderSum();
        short newCheckSum = ByteUtils.checksum(sum, data, headerLen, getDataLen());
        udpWrapper.setCheckSum(newCheckSum);
        return oldCheckSum == newCheckSum;
    }

    /**
     * 计算伪首部和
     */
    public long computePseudoHeaderSum(){
        long sum = ByteUtils.getsum(data, offset + 12, 8);
        sum += getProtocol() & 0xFF;
        sum += getDataLen();
        return sum;
    }





    public static String mapProtocolStr(int protocol){
        switch (protocol){
            case 1:
                return "ICMP";
            case 6:
                return "TCP";
            case 17:
                return "UDP";
            default:
                return "unknown:"+protocol;
        }
    }



    @SuppressLint("DefaultLocale")
    public String print(){
        return String.format("\tv:%d\theaderLen:%d\tTOS:%d\ttotalLen:%d\n" +
                        "\tid:%d\tflag:%d\toffset:%d\n" +
                        "\tTTL:%d\tProtocol:%s\tcheckSum:%d\n" +
                        "\tsrcAddress:%s\n" +
                        "\tdestAddress:%s\n\t%s\n",
                getVersion(), getHeaderLen(), getTOS(), getTotalLen(),
                getIdentifier(),getFlag(),getOffset(),
                getTTL(), IPWrapper.mapProtocolStr(getProtocol()), getCheckSum(),
                Utils.ipIntToInet4Address(getSrcAddress()),
                Utils.ipIntToInet4Address(getDestAddress()),
                printTCPorUDP());
    }

    @SuppressLint("DefaultLocale")
    @Override
    public String toString() {
        return String.format("[%s] [%s:%d] -> [%s:%d] size:%d",
                mapProtocolStr(getProtocol()),
                Utils.ipIntToString(getSrcAddress()),
                getSrcPort(),
                Utils.ipIntToString(getDestAddress()),
                getDestPort(), getTotalLen());
    }

    private int getSrcPort(){
        int protocol = getProtocol();
        switch (protocol){
            case Const.IP_TCP_PROTOCOL:
            case Const.IP_UDP_PROTOCOL:
                tcpWrapper.withData(data, getHeaderLen());
                return tcpWrapper.getSrcPort();
            default:
                return 0;
        }
    }

    private int getDestPort(){
        int protocol = getProtocol();
        switch (protocol){
            case Const.IP_TCP_PROTOCOL:
            case Const.IP_UDP_PROTOCOL:
                tcpWrapper.withData(data, getHeaderLen());
                return tcpWrapper.getDestPost();
            default:
                return 0;
        }
    }


    private String printTCPorUDP(){
        switch (getProtocol()){
            case Const.IP_TCP_PROTOCOL:
                TCPWrapper tcpWrapper = getTCPWrapper();
                return "TCP:\n"+ tcpWrapper.print();
            case Const.IP_UDP_PROTOCOL:
                UDPWrapper udpWrapper = getUDPWrapper();
                return "UDP:\n"+udpWrapper.print();
        }
        return "OTHERS";
    }
}
