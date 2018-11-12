package com.grumpycat.pcap;

import android.annotation.SuppressLint;
import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;

/**
 * Created by cc.he on 2018/8/29
 */
public class TCPProxy implements Runnable{
    private int port;
    private String ip;
    private ServerSocketChannel ssc;
    private Selector selector;
    private SocketProtector protector;
    private ScheduledThreadPoolExecutor executor;

    public TCPProxy(SocketProtector protector) {
        this.protector = protector;
        this.executor = new ScheduledThreadPoolExecutor(30, new ThreadFactory() {
            @Override
            public Thread newThread(@NonNull Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("TCPProxy_Executor");
                return thread;
            }
        });

        GrumpyPcap.getInstance().startObserve(executor);
    }

    public void startWork() throws IOException {
        selector = Selector.open();
        ssc = ServerSocketChannel.open();
        ssc.configureBlocking(false);
        ssc.socket().bind(new InetSocketAddress(Const.RANDOM_PORT));
        ssc.register(selector, SelectionKey.OP_ACCEPT);

        this.port = ssc.socket().getLocalPort();
        ip = ssc.socket().getInetAddress().getHostAddress();

        GrumpyPcap.OnVPNListener onVPNListener = GrumpyPcap.getInstance().getOnVPNListener();
        if (onVPNListener != null){
            onVPNListener.onTcpProxyStarted(this);
        }

        Thread thread = new Thread(this);
        thread.setName("Grumpy-TCPProxy");
        thread.setDaemon(true);
        thread.start();
    }


    public int getPort() {
        return port;
    }

    @Override
    public void run() {
        while (true) {
            try {
                pollSelect();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
            }
        }
    }

    private void pollSelect() throws Exception{
        int select = selector.select();
        if (select == 0) {
            return;
        }

        Set<SelectionKey> selectionKeys = selector.selectedKeys();
        if (selectionKeys == null || selectionKeys.size() == 0) {
            return;
        }

        Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
        while (iterator.hasNext()) {
            SelectionKey key = iterator.next();
            if (key.isValid()) {
                if (key.isAcceptable()) {
                    executeProxyBlock();
                }else if (key.attachment() instanceof ProxyTunnel){
                    ProxyTunnel tunnel = (ProxyTunnel) key.attachment();
                    try {
                        tunnel.onSelected(key);
                    }catch (Exception e){
                        e.printStackTrace();
                        tunnel.close(e.getMessage());
                    }
                }
            }
            iterator.remove();
        }
    }

    private void executeProxy() {
        try {
            SocketChannel proxyChannel = ssc.accept();

            int port = proxyChannel.socket().getPort();
            SessionManager sm = SessionManager.getInstance();
            ProxySession session = sm.getSession(port);
            if (session != null){
                InetAddress address = proxyChannel.socket().getInetAddress();

                Log.e("pxyrec", "["+address.getHostAddress()+":"+port+"]");

                InetSocketAddress remote = new InetSocketAddress(address, session.getDestPost());
                SocketChannel remoteChannel = SocketChannel.open();
                protector.protect(remoteChannel.socket());
                ProxyTunnel tunnel = new ProxyTunnel(proxyChannel, remoteChannel, selector);

                tunnel.establish(remote);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void executeProxyBlock(){
        try {
            SocketChannel proxyChannel = ssc.accept();

            int port = proxyChannel.socket().getPort();
            SessionManager sm = SessionManager.getInstance();
            ProxySession session = sm.getSession(port);
            if (session != null) {
                InetAddress address = proxyChannel.socket().getInetAddress();
                InetSocketAddress remote = new InetSocketAddress(address, session.getDestPost());
                SocketChannel remoteChannel = SocketChannel.open();
                protector.protect(remoteChannel.socket());

                TunnelWorker worker = new TunnelWorker(proxyChannel, remoteChannel, remote);
                worker.launchTunnel(executor);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    @SuppressLint("DefaultLocale")
    @Override
    public String toString() {
        return String.format("TCP_Proxy [%s:%d]", ip, port);
    }
}
