package com.grumpycat.pcap;

import android.annotation.SuppressLint;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Created by cc.he on 2018/8/30
 */
public class ProxySession {
    private int srcIp;
    private int srcPort;
    private int destIp;
    private int destPost;
    private ConcurrentLinkedQueue<byte[]> packetList;

    private ConcurrentLinkedQueue<byte[]> socketPacketList;

    public ProxySession(int srcIp, int srcPort, int destIp, int destPost) {
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.destIp = destIp;
        this.destPost = destPost;
    }

    public ProxySession(int srcPort, int destIp, int destPost) {
        this.srcPort = srcPort;
        this.destIp = destIp;
        this.destPost = destPost;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDestIp() {
        return destIp;
    }

    public int getDestPost() {
        return destPost;
    }

    public void addPacket(byte[] data){
        if (packetList == null){
            packetList = new ConcurrentLinkedQueue<>();
        }
        packetList.offer(data);
    }

    public void addSocketPacket(byte[] data){
        if (socketPacketList == null){
            socketPacketList = new ConcurrentLinkedQueue<>();
        }
        socketPacketList.offer(data);
    }

    public int getSrcIp() {
        return srcIp;
    }

    @SuppressLint("DefaultLocale")
    @Override
    public String toString() {
        return String.format("[%s:%d] -> [%s:%d]",
                Utils.ipIntToString(srcIp),
                getSrcPort(),
                Utils.ipIntToString(destIp),
                destPost);
    }

    public String print(){
        StringBuilder sb = new StringBuilder();
        IPWrapper ipWrapper = new IPWrapper();
        for(byte[] data:packetList){
            ipWrapper.withData(data);
            sb.append(ipWrapper.toString()).append("\n");
            int offset = ipWrapper.getHeaderLen()+ipWrapper.getTCPWrapper().getHeaderLen();
            if (offset < data.length){
                sb.append(new String(data, offset, data.length - offset)).append("\n\n");
            }else{
                sb.append("no data\n");
            }
        }
        return sb.toString();
    }

    public String printSocket(){
        if (socketPacketList == null){
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for(byte[] data:socketPacketList){
            sb.append(new String(data)).append("\n");
        }
        return sb.toString();
    }
}
