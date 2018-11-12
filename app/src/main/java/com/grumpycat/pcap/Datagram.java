package com.grumpycat.pcap;

import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by cc.he on 2018/9/21
 */
public class Datagram {
    private IPWrapper ipWrapper;
    public Datagram(byte[] data){
        ipWrapper = new IPWrapper();
        ipWrapper.withData(data);
    }

    public static Datagram wrap(byte[] data){
        return new Datagram(data);
    }

    public static Datagram copy(Datagram from){
        byte[] src = from.getIpWrapper().getData();
        byte[] data = Utils.copyData(src, 0, src.length);
        return new Datagram(data);
    }


    public void swapAddressAndPort(){
        UDPWrapper udpWrapper = ipWrapper.getUDPWrapper();
        int tmp = ipWrapper.getSrcAddress();
        ipWrapper.setSrcAddress(ipWrapper.getDestAddress());
        ipWrapper.setDestAddress(tmp);

        tmp = udpWrapper.getSrcPort();
        udpWrapper.setSrcPort(udpWrapper.getDestPost());
        udpWrapper.setDestPort(tmp);
    }

    public void setUdpData(byte[] data, int offset, int len){
        UDPWrapper udpWrapper = ipWrapper.getUDPWrapper();
        int destOffset = ipWrapper.getHeaderLen()+8;
        Utils.copyValue(data, offset, ipWrapper.getData(), destOffset, len);
        udpWrapper.setLen(len+8);
        ipWrapper.setTotalLen(ipWrapper.getHeaderLen()+len+8);
    }

    public void calculateChecksum(){
        ipWrapper.computeIPCheckSum();
        ipWrapper.computeUDPCheckSum();
    }

    public IPWrapper getIpWrapper() {
        return ipWrapper;
    }

    public void writeTo(FileOutputStream fos) throws IOException {
        byte[] data = ipWrapper.getData();
        fos.write(data, 0, ipWrapper.getTotalLen());
    }
}
