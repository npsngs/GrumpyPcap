package com.grumpycat.pcap;

import java.net.Socket;
import java.nio.channels.SocketChannel;

/**
 * Created by cc.he on 2018/9/10
 */
public class StringUtils {
    public static String print(SocketChannel socketChannel){
        Socket socket = socketChannel.socket();
        int port = socketChannel.socket().getPort();
        String address = socket.isConnected()?
                socket.getInetAddress().getHostAddress()
                :"unconnected";
        return "["+address+":"+port+"]";
    }
}
