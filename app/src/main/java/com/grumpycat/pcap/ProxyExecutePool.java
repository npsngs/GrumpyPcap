package com.grumpycat.pcap;

import android.support.annotation.NonNull;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Created by cc.he on 2018/9/19
 */
public class ProxyExecutePool {
    private Executor executor;
    public ProxyExecutePool() {
        this.executor = Executors.newScheduledThreadPool(20, new ThreadFactory() {
            @Override
            public Thread newThread(@NonNull Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("TCPProxy_Executor");
                return thread;
            }
        });
    }

    public void execute(){
    }

}
