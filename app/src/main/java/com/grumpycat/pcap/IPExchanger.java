package com.grumpycat.pcap;

import android.annotation.SuppressLint;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.forthe.xlog.XLog;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by cc.he on 2018/8/29
 */
public class IPExchanger {
    private ParcelFileDescriptor descriptor;

    private int VPN_IP;
    private int LOCAL_IP;
    private IPWrapper ipWrapper;
    private TCPProxy tcpProxy;
    private UDPProxy2 udpProxy;
    private UDPProxy udpProxy1;

    private FileOutputStream fos;
    private FileInputStream fis;
    public IPExchanger(SocketProtector protector) {
        ipWrapper = new IPWrapper();

        VPN_IP = Utils.ipStringToInt(Const.VPN_IP4);
        LOCAL_IP = Utils.getLocalIP();

        tcpProxy = new TCPProxy(protector);
        udpProxy = new UDPProxy2(protector);
        udpProxy1 = new UDPProxy(protector);
    }

    public void startPacketCapture(ParcelFileDescriptor descriptor){
        this.descriptor = descriptor;
        startTCPProxy();
        startUDPProxy();
        startVPNReader();
    }

    public void startTCPProxy(){
        try {
            tcpProxy.startWork();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void startUDPProxy(){
        try {
            udpProxy1.startWork();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void startVPNReader(){
        Thread thread = new Thread(){
            @Override
            public void run() {
                try {
                    readPacketFromVPN();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        };
        thread.setName("Grumpy-VPNReader");
        thread.setDaemon(true);
        thread.start();
    }


    private void readPacketFromVPN() throws Exception {
        FileDescriptor fileDescriptor = descriptor.getFileDescriptor();
        fis = new FileInputStream(fileDescriptor);
        fos = new FileOutputStream(fileDescriptor);

        byte[] buffer = new byte[Const.MTU];
        int ret;
        while ((ret = fis.read(buffer)) >= 0){
            if (ret == 0) {
                //writeUdpPacket();
                continue;
            }

            ipWrapper.withData(buffer);
            switch (ipWrapper.getProtocol()){
                case Const.IP_TCP_PROTOCOL:
                    //Log.e("r_tcp", ipWrapper.toString()+"  size:"+ret);
                    handleTcpPacket(ipWrapper);
                    break;
                case Const.IP_UDP_PROTOCOL:
                    //Log.e("r_udp", ipWrapper.toString()+"  size:"+ret);
                    handleUdpPacket(ipWrapper);
                    break;
            }

            Thread.sleep(10);
        }
        fis.close();
    }


    private void handleTcpPacket(IPWrapper ipWrapper) throws IOException {
        if (isTCPFromProxy(ipWrapper)){
            exchangeTcpPacket(ipWrapper);
        }else{
            sendToTcpProxy();
        }
    }

    private void handleUdpPacket(IPWrapper ipWrapper) throws Exception {
        if(isUDPFromProxy(ipWrapper)){
            exchangeUdpPacket(ipWrapper);
        }else{
            sendToUdpProxy();
        }
    }

    private void exchangeTcpPacket(IPWrapper ipWrapper) throws IOException {
        TCPWrapper tcpWrapper = ipWrapper.getTCPWrapper();
        int sessionKey = tcpWrapper.getDestPost();
        SessionManager sm = SessionManager.getInstance();
        ProxySession session = sm.getSession(sessionKey);
        if (session != null){
            ipWrapper.setSrcAddress(session.getDestIp());
            tcpWrapper.setSrcPort(session.getDestPost());
            ipWrapper.setDestAddress(LOCAL_IP);

            Utils.assertTrue(session.getSrcPort() == tcpWrapper.getDestPost());

            ipWrapper.computeIPCheckSum();
            ipWrapper.computeTCPCheckSum();

            Log.d("exchange", buildDetailTcpStr(ipWrapper));
            session.addPacket(Utils.copyData(ipWrapper.getData(), 0, ipWrapper.getTotalLen()));
            fos.write(ipWrapper.getData(), ipWrapper.getOffset(), ipWrapper.getTotalLen());
        }
    }

    @SuppressLint("DefaultLocale")
    private String buildDetailTcpStr(IPWrapper ipWrapper){
        String s = "";
        TCPWrapper tcpWrapper = ipWrapper.getTCPWrapper();
        s += String.format("[%s:%d --> %s:%d] ",
                Utils.ipIntToString(ipWrapper.getSrcAddress()),
                tcpWrapper.getSrcPort(),
                Utils.ipIntToString(ipWrapper.getDestAddress()),
                tcpWrapper.getDestPost());
        s += tcpWrapper.print();
        s += "\n";
        int totalLen = ipWrapper.getTotalLen();
        int ipHLen = ipWrapper.getHeaderLen();
        int tcpHLen = tcpWrapper.getHeaderLen();
        int dataLen = totalLen - ipHLen - tcpHLen;
        if (dataLen > 0){
            s += HexStr.bytes2Hex(ipWrapper.getData(), ipHLen+tcpHLen, dataLen);
            s += "\n";
            s += new String(ipWrapper.getData(), ipHLen+tcpHLen, dataLen);
            s += "\n";
        }
        return s;
    }





    private boolean isTCPFromProxy(IPWrapper ipWrapper){
        TCPWrapper tcpWrapper = ipWrapper.getTCPWrapper();

        if (tcpWrapper.getSrcPort() == tcpProxy.getPort()){
            return true;
        }

        if (tcpWrapper.getDestPost() == tcpProxy.getPort()){
            XLog.d("vpn", "dest to TCP proxy");
        }else{
            if (isLocalIp(ipWrapper.getSrcAddress())){
                XLog.d("vpn", "send real packet");
            }else{
                XLog.d("vpn", "receive real packet");
            }
        }

        return false;
    }


    private boolean isUDPFromProxy(IPWrapper ipWrapper){
        UDPWrapper wrapper = ipWrapper.getUDPWrapper();

        if (wrapper.getSrcPort() == udpProxy1.getPort()){
            return true;
        }

        if (wrapper.getDestPost() == udpProxy1.getPort()){
            XLog.d("vpn", "dest to UDP proxy");
        }else{
            if (isLocalIp(ipWrapper.getSrcAddress())){
                XLog.d("vpn", "send real udp packet");
            }else{
                XLog.d("vpn", "receive udp real packet");
            }
        }

        return false;
    }

    private void sendToTcpProxy() throws IOException {
        Log.e("send2proxy", buildDetailTcpStr(ipWrapper));

        TCPWrapper tcpWrapper = ipWrapper.getTCPWrapper();
        int srcPort = tcpWrapper.getSrcPort();
        SessionManager sm = SessionManager.getInstance();
        ProxySession session = sm.getSession(srcPort);

        if (session == null){
            session = new ProxySession(
                    ipWrapper.getSrcAddress(),
                    srcPort,
                    ipWrapper.getDestAddress(),
                    tcpWrapper.getDestPost());
            sm.putSession(srcPort, session);
        }

        session.addPacket(Utils.copyData(ipWrapper.getData(), 0, ipWrapper.getTotalLen()));

        if (ipWrapper.getSrcAddress() != LOCAL_IP){
            XLog.d("ipne", "src:" + Utils.ipIntToString(ipWrapper.getSrcAddress()) +
                            " local:"+Utils.ipIntToString(LOCAL_IP));
        }



        ipWrapper.setSrcAddress(ipWrapper.getDestAddress());
        ipWrapper.setDestAddress(VPN_IP);
        tcpWrapper.setDestPort(tcpProxy.getPort());

        ipWrapper.computeIPCheckSum();
        ipWrapper.computeTCPCheckSum();

        byte[] data = ipWrapper.getData();
        int offset = ipWrapper.getOffset();
        fos.write(data, offset, ipWrapper.getTotalLen());
    }


    private void exchangeUdpPacket(IPWrapper ipWrapper) throws IOException {
        UDPWrapper udpWrapper = ipWrapper.getUDPWrapper();
        int sessionKey = udpWrapper.getDestPost();
        SessionManager sm = SessionManager.getInstance();
        ProxySession session = sm.getSession(sessionKey);
        if (session != null){
            ipWrapper.setSrcAddress(session.getDestIp());
            udpWrapper.setSrcPort(session.getDestPost());
            ipWrapper.setDestAddress(LOCAL_IP);

            Utils.assertTrue(session.getSrcPort() == udpWrapper.getDestPost());

            ipWrapper.computeIPCheckSum();
            ipWrapper.computeTCPCheckSum();

            Log.e("exchange", ipWrapper.toString() + "size:"+ipWrapper.getTotalLen());
            //session.addPacket(Utils.copyData(ipWrapper.getData(), 0, ipWrapper.getTotalLen()));
            fos.write(ipWrapper.getData(), ipWrapper.getOffset(), ipWrapper.getTotalLen());
        }
    }


    private void sendToUdpProxy() throws Exception{
        Log.e("sd2pxy", "ipWrapper:"+ipWrapper.toString());

        UDPWrapper udpWrapper = ipWrapper.getUDPWrapper();
        int srcPort = udpWrapper.getSrcPort();
        SessionManager sm = SessionManager.getInstance();
        ProxySession session = sm.getSession(srcPort);

        if (session == null
                || ipWrapper.getDestAddress() != session.getDestIp()
                || udpWrapper.getDestPost() != session.getDestPost()){
            session = new ProxySession(
                    ipWrapper.getSrcAddress(),
                    srcPort,
                    ipWrapper.getDestAddress(),
                    udpWrapper.getDestPost());
            sm.putSession(srcPort, session);
        }
        //session.addPacket(Utils.copyData(ipWrapper.getData(), 0, ipWrapper.getTotalLen()));

        if (ipWrapper.getSrcAddress() != LOCAL_IP){
            XLog.d("ipne", "src:" + Utils.ipIntToString(ipWrapper.getSrcAddress()) +
                    " local:"+Utils.ipIntToString(LOCAL_IP));
        }



        ipWrapper.setSrcAddress(ipWrapper.getDestAddress());
        ipWrapper.setDestAddress(VPN_IP);
        udpWrapper.setDestPort(udpProxy1.getPort());

        ipWrapper.computeIPCheckSum();
        ipWrapper.computeUDPCheckSum();

        byte[] data = ipWrapper.getData();
        int offset = ipWrapper.getOffset();
        fos.write(data, offset, ipWrapper.getTotalLen());
    }


    public void shutdown(){
        try {
            descriptor.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    private boolean isLocalIp(int ip){
        return ip == VPN_IP || ip == LOCAL_IP;
    }
}
