package com.grumpycat.pcap;

import android.support.annotation.NonNull;
import android.util.Log;

import com.forthe.xlog.XLog;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Created by cc.he on 2018/8/29
 */
public class UDPProxy2 {
    private final String TAG = "udpp";

    private ConcurrentLinkedQueue<Datagram> sendCache;
    private ConcurrentLinkedQueue<Datagram> receiveCache;
    private SocketProtector protector;
    private Executor executor;

    public UDPProxy2(SocketProtector protector) {
        this.protector = protector;
        sendCache = new ConcurrentLinkedQueue<>();
        receiveCache = new ConcurrentLinkedQueue<>();
        this.executor = Executors.newScheduledThreadPool(10, new ThreadFactory() {
            @Override
            public Thread newThread(@NonNull Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("UDPProxy_Executor");
                return thread;
            }
        });
    }

    public void send(byte[] data){
        Datagram datagram = Datagram.wrap(data);
        XLog.d(TAG, "send:" + datagram.getIpWrapper().toString());
        sendCache.offer(datagram);
        executor.execute(new UDPWorker());
    }

    public Datagram pollReceivedData(){
        Datagram datagram = receiveCache.poll();
        if (datagram != null)
            XLog.d(TAG, "receive:" + datagram.getIpWrapper().toString());
        return datagram;
    }

    private class UDPWorker implements Runnable{
        @Override
        public void run() {
            Datagram datagram = sendCache.poll();
            if (datagram == null){
                return;
            }
            try {
                sendDatagram(datagram);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    private void sendDatagram(Datagram datagram) throws IOException {
        IPWrapper ipWrapper = datagram.getIpWrapper();
        UDPWrapper udpWrapper = ipWrapper.getUDPWrapper();
        InetSocketAddress remote = new InetSocketAddress(
                Utils.ipIntToInet4Address(ipWrapper.getDestAddress()),
                udpWrapper.getDestPost());
        DatagramChannel dc = DatagramChannel.open();
        dc.socket().bind(new InetSocketAddress(Const.RANDOM_PORT));
        dc.socket().setSoTimeout(10000);
        protector.protect(dc.socket());
        dc.connect(remote);

        int dataLen = udpWrapper.getLen() - 8;
        int offset = ipWrapper.getTotalLen() - dataLen;
        int ret = dc.send(ByteBuffer.wrap(ipWrapper.getData(), offset, dataLen), remote);
        if (ret <= 0){
            closeChannel(dc);
            return;
        }

        XLog.d(TAG, "sendDatagram:" + datagram.getIpWrapper().toString());

        ByteBuffer buffer = ByteBuffer.allocate(Const.MTU);
        try {
            while ((ret = dc.read(buffer)) > 0){
                Datagram recv = Datagram.copy(datagram);
                recv.setUdpData(buffer.array(), 0, ret);
                recv.swapAddressAndPort();
                recv.calculateChecksum();
                receiveCache.offer(recv);
                XLog.d(TAG, "receiveDatagram:" + recv.getIpWrapper().toString());
                buffer.clear();
            }
            closeChannel(dc);
        }catch (Exception e){
            closeChannel(dc);
            e.printStackTrace();
        }
    }

    private void closeChannel(DatagramChannel dc){
        try {
            Log.e("close_udp", "size:0");
            dc.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
