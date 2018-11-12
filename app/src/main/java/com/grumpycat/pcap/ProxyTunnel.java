package com.grumpycat.pcap;

import android.util.Log;

import com.forthe.xlog.XLog;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.Queue;

/**
 * Created by cc.he on 2018/8/30
 */
public class ProxyTunnel {
    private SocketChannel proxyChannel;
    private SocketChannel remoteChannel;
    private Selector selector;
    private ByteBuffer buffer;
    private Queue<ByteBuffer> write2RemoteCache;
    private Queue<ByteBuffer> write2ProxyCache;
    private int portKey;
    private SessionManager sm;

    public ProxyTunnel(SocketChannel proxyChannel
            , SocketChannel remoteChannel
            , Selector selector) {
        this.proxyChannel = proxyChannel;
        this.remoteChannel = remoteChannel;
        this.selector = selector;
        buffer = ByteBuffer.allocate(Const.MTU);

        write2ProxyCache = new LinkedList<>();
        write2RemoteCache = new LinkedList<>();
        portKey = proxyChannel.socket().getPort();
        sm = SessionManager.getInstance();
    }

    public void establish(SocketAddress remote) throws IOException {
        remoteChannel.configureBlocking(false);
        remoteChannel.register(selector,
                SelectionKey.OP_CONNECT,
                this);
        remoteChannel.connect(remote);
    }

    public void onSelected(SelectionKey key) throws IOException {
        Log.e("skey", Integer.toBinaryString(key.readyOps()));


        if (key.isConnectable()
                && key.channel() == remoteChannel
                && remoteChannel.finishConnect()){

            proxyChannel.configureBlocking(false);
            selector.wakeup();
            proxyChannel.register(selector,
                    SelectionKey.OP_READ,
                    this);
            Log.e("slt", "[rm_con] "+StringUtils.print(remoteChannel));

        }


        if (key.isReadable()){
            if (key.channel() == proxyChannel){
                buffer.clear();
                int size = proxyChannel.read(buffer);
                if (size > 0){
                    buffer.flip();
                    write2Remote(buffer);
                }else if(size < 0){
                    close("read proxy size = -1");
                }
                XLog.d("slt", "[px_read] "+"size:"+size);
            }else if(key.channel() == remoteChannel){
                buffer.clear();
                int size = remoteChannel.read(buffer);
                if (size > 0){
                    buffer.flip();
                    write2Proxy(buffer);
                }else if(size < 0){
                    close("read remote size = -1");
                }
                XLog.d("slt", "[rm_read] "+"size:"+size);
            }
        }



        if (key.isWritable()){
            if (key.channel() == proxyChannel){
                write2Proxy();
            }else if(key.channel() == remoteChannel){
                write2Remote();
            }
        }
    }

    private void write2Proxy(ByteBuffer buffer) throws IOException {
        ProxySession session = sm.remove(portKey);
        if (session != null){
            byte[] data = Utils.copyData(buffer);
            session.addSocketPacket(Utils.copyData(buffer));
            Log.e("recvs", new String(data));
        }


        if (!write2ProxyCache.isEmpty()){
            appendCache(buffer, write2ProxyCache, proxyChannel);
            return;
        }

        int ret;
        try {
            ret = write2Channel(buffer, proxyChannel);
        }catch (Exception e){
            ret = 0;
            e.printStackTrace();
        }
        XLog.d("slt", "[rm_write][w_total] "+"size:"+ret);

        if (ret <= 0){
            appendCache(buffer, write2ProxyCache, proxyChannel);
        }
    }

    private void write2Proxy() throws IOException {
        int count = 0;
        while (!write2ProxyCache.isEmpty()){
            int ret = write2Channel(write2ProxyCache.poll(), proxyChannel);
            count += ret;
        }
        Log.e("slt", "[px_write][w_total] "+"size:"+count);
    }



    private void write2Remote(ByteBuffer buffer) throws IOException {
        ProxySession session = sm.remove(portKey);
        if (session != null){
            byte[] data = Utils.copyData(buffer);
            session.addSocketPacket(Utils.copyData(buffer));
            Log.e("snds", new String(data));
        }


        if (!write2RemoteCache.isEmpty()){
            appendCache(buffer, write2RemoteCache, remoteChannel);
            return;
        }


        int ret;
        try {
            ret = write2Channel(buffer, remoteChannel);
        }catch (Exception e){
            ret = 0;
            e.printStackTrace();
        }


        XLog.d("slt", "[rm_write] "+"size:"+ret);
        if(ret <= 0){
            appendCache(buffer, write2RemoteCache, remoteChannel);
        }
    }


    private void appendCache(ByteBuffer buffer,
                             Queue<ByteBuffer> cache,
                             SocketChannel channel) throws IOException{
        cache.add(Utils.copyByteBuffer(buffer));
        selector.wakeup();
        channel.register(
                selector,
                SelectionKey.OP_READ|SelectionKey.OP_WRITE,
                this);
    }



    private void write2Remote() throws IOException {
        int count = 0;
        while (!write2RemoteCache.isEmpty()){
            int ret = write2Channel(write2RemoteCache.poll(), remoteChannel);
            count += ret;
        }
        XLog.d("slt", "[rm_write][w_total] "+"size:"+count);
    }

    private int write2Channel(ByteBuffer buffer, SocketChannel channel) throws IOException {
        int count = 0;
        while (buffer.hasRemaining()){
            int ret = channel.write(buffer);
            if (ret == 0){
                break;
            }
            count += ret;
        }
        return count;
    }


    public void close(String cause) throws IOException {
        remoteChannel.close();
        proxyChannel.close();
        ProxySession session = sm.remove(portKey);
        if (session != null)
            Log.e("shutd", "cause:"+cause +"  " + session.printSocket());
    }
}
