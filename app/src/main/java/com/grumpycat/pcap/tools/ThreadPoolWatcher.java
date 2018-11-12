package com.grumpycat.pcap.tools;

import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by cc.he on 2018/9/28
 */
public class ThreadPoolWatcher{
    private ThreadPoolExecutor executor;
    private Messager messager;
    private volatile boolean isStop;
    public ThreadPoolWatcher(ThreadPoolExecutor executor, Messager messager) {
        this.executor = executor;
        this.messager = messager;
    }

    public void start(){
        isStop = false;
        new Thread("ThreadPool-Watcher"){
            @Override
            public void run() {
                try {
                    while (!isStop){
                        long poolSize = executor.getPoolSize();
                        int queueSize = executor.getQueue().size();
                        int activeCount = executor.getActiveCount();
                        long completedTaskCount = executor.getCompletedTaskCount();
                        long taskCount = executor.getTaskCount();

                        String s = "";
                        s += "\nPoolSize：" + poolSize;
                        s += "\nqueueSize：" + queueSize;
                        s += "\nactiveCount：" + activeCount;
                        s += "\ncompletedTaskCount：" + completedTaskCount;
                        s += "\ntotalTaskCount：" + taskCount;
                        messager.onMessage(s);

                        sleep(1000);
                    }
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }.start();
    }
}
