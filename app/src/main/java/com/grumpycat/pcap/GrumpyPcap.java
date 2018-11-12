package com.grumpycat.pcap;

import com.grumpycat.pcap.tools.Messager;
import com.grumpycat.pcap.tools.ThreadPoolWatcher;

import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by cc.he on 2018/9/10
 */
public class GrumpyPcap {
    private static GrumpyPcap _instance = new GrumpyPcap();
    public static GrumpyPcap getInstance(){
        return _instance;
    }

    private GrumpyPcap() {}
    private OnVPNListener onVPNListener;
    private Messager tcpThreadPoolMessager;
    public void setTcpThreadPoolMessager(Messager messager) {
        this.tcpThreadPoolMessager = messager;
    }

    public void setOnVPNListener(OnVPNListener onVPNListener) {
        this.onVPNListener = onVPNListener;
    }

    public interface OnVPNListener{
        void onTcpProxyStarted(TCPProxy tcpProxy);
    }

    public OnVPNListener getOnVPNListener() {
        return onVPNListener;
    }

    public void startObserve(ThreadPoolExecutor tpe){
        new ThreadPoolWatcher(tpe, tcpThreadPoolMessager).start();
    }
}
