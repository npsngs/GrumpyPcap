package com.grumpycat.pcap;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Created by cc.he on 2018/9/26
 */
public class UDPProxy{
    private SocketProtector protector;
    private int port;

    public UDPProxy(SocketProtector protector) {
        this.protector = protector;
    }

    private DatagramSocket localProxy, remoteProxy;
    private DatagramPacket localPacket, remotePacket;
    private SessionManager sm;
    public void startWork() throws IOException {
        localProxy = new DatagramSocket(0);
        remoteProxy = new DatagramSocket(0);
        protector.protect(remoteProxy);
        port = localProxy.getLocalPort();

        localPacket = new DatagramPacket(new byte[Const.MTU], Const.MTU);
        remotePacket = new DatagramPacket(new byte[Const.MTU], Const.MTU);
        sm = SessionManager.getInstance();

        Thread thread1 = new Thread(new TunnelAction(localProxy, remoteProxy, localPacket,true));
        thread1.setName("Grumpy-UDPProxy1");
        thread1.setDaemon(true);
        thread1.start();

        Thread thread2 = new Thread(new TunnelAction(remoteProxy, localProxy, remotePacket,false));
        thread2.setName("Grumpy-UDPProxy2");
        thread2.setDaemon(true);
        thread2.start();
    }


    private class TunnelAction implements Runnable{
        private DatagramSocket recvDc, sendDc;
        private DatagramPacket recvDp;
        private boolean isFromLocal;
        public TunnelAction(DatagramSocket recvDc,
                            DatagramSocket sendDc,
                            DatagramPacket recvDp,
                            boolean isFromLocal) {
            this.recvDc = recvDc;
            this.sendDc = sendDc;
            this.recvDp = recvDp;
            this.isFromLocal = isFromLocal;
        }

        @Override
        public void run() {
            try {
                while (true){
                    recvDc.receive(recvDp);
                    ProxySession session = sm.getSession(recvDp.getPort());
                    if (session == null){
                        continue;
                    }
                    InetAddress address;
                    int port;
                    if (isFromLocal){
                        address = Utils.ipIntToInet4Address(session.getDestIp());
                        port = session.getDestPost();
                    }else{
                        address = Utils.ipIntToInet4Address(session.getSrcIp());
                        port = session.getSrcPort();
                    }

                    sendDc.send(new DatagramPacket(
                            recvDp.getData(),
                            recvDp.getLength(),
                            address,
                            port));
                }
            }catch (Exception e){
                e.printStackTrace();
                safeClose();
            }
        }

        private void safeClose(){
            try {
                recvDc.close();
                sendDc.close();
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public int getPort() {
        return port;
    }


}
