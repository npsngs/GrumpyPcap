package com.grumpycat.pcap;

import java.net.DatagramSocket;
import java.net.Socket;

/**
 * Created by cc.he on 2018/8/29
 */
public interface SocketProtector {
    boolean protect(int socket);
    boolean protect(Socket socket);
    boolean protect(DatagramSocket socket);
}
