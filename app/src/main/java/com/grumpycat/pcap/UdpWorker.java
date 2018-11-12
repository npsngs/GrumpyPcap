package com.grumpycat.pcap;

import java.net.DatagramSocket;

/**
 * Created by cc.he on 2018/9/26
 */
public class UdpWorker implements Runnable{
    private DatagramSocket local;
    private DatagramSocket remote;

    public UdpWorker(DatagramSocket local, DatagramSocket remote) {
        this.local = local;
        this.remote = remote;
    }

    @Override
    public void run() {

    }
}
