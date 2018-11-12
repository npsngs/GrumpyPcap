package com.grumpycat.pcap;

import android.text.TextUtils;
import android.util.Log;
import android.widget.TextView;

import com.forthe.xlog.XLog;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;

/**
 * Created by cc.he on 2018/9/19
 */
public class TunnelWorker{
    private static final int OP_CONNECT =       1;
    private static final int OP_READ_LOCAL =    2;
    private static final int OP_READ_REMOTE =   3;
    private class Operator implements Runnable{
        private int op;
        public Operator(int op) {
            this.op = op;
        }

        @Override
        public void run() {
            switch (op){
                case OP_CONNECT:
                    connect2Remote();
                    break;
                case OP_READ_LOCAL:
                    readFromLocal();
                    break;
                case OP_READ_REMOTE:
                    readFromRemote();
                    break;
            }
        }
    }

    private final String TAG = "twk";

    private SocketChannel proxyChannel;
    private SocketChannel remoteChannel;
    private SocketAddress remote;
    private  ByteBuffer bufferL,bufferR;


    private Operator readLocalOp;
    private Operator readRemoteOp;
    public TunnelWorker(SocketChannel proxyChannel,
                        SocketChannel remoteChannel,
                        SocketAddress remote) {

        this.proxyChannel = proxyChannel;
        this.remoteChannel = remoteChannel;

        this.remote = remote;
    }

    private Executor executor;
    public void launchTunnel(Executor executor){
        this.executor = executor;
        executor.execute(new Operator(OP_CONNECT));
        Log.e(TAG, "start tunnel work ["+remote.toString()+"]");
    }


    private void connect2Remote(){
        try {
           boolean isSuccess = remoteChannel.connect(remote);
           if (isSuccess){
               readLocalOp = new Operator(OP_READ_LOCAL);
               readRemoteOp = new Operator(OP_READ_REMOTE);
               proxyChannel.socket().setSoTimeout(6000);
               remoteChannel.socket().setSoTimeout(8000);
               executor.execute(readLocalOp);
               executor.execute(readRemoteOp);
               XLog.d(TAG, "connect");
           }else{
               close("connect failed");
           }
        } catch (IOException e) {
            close(e.getMessage());
            e.printStackTrace();
        }
    }


    private void readFromLocal(){
        if (bufferL == null){
            bufferL = ByteBuffer.allocate(Const.MTU);
        }
        try {
            bufferL.clear();
            int ret = proxyChannel.read(bufferL);
            XLog.d(TAG, "readLocal size:"+ret);
            if (ret > 0){
                write2Remote();
                executor.execute(readLocalOp);
            }else if(ret < 0){
                close("local read count < 0");
            }
        } catch (IOException e) {
            close(e.getMessage());
            e.printStackTrace();
        }
    }


    private void readFromRemote(){
        if (bufferR == null){
            bufferR = ByteBuffer.allocate(Const.MTU);
        }
        try {
            bufferR.clear();
            int ret = remoteChannel.read(bufferR);
            XLog.d(TAG, "readRemote size:"+ret);
            if (ret > 0){
                write2Local();
                executor.execute(readRemoteOp);
            }else if(ret < 0){
                close("remote read count < 0");
            }
        } catch (IOException e) {
            close(e.getMessage());
            e.printStackTrace();
        }
    }


    private void write2Local() throws IOException {
        bufferR.flip();
        int ret = proxyChannel.write(bufferR);
        XLog.d(TAG, "write2Local size:"+ret);
    }


    private void write2Remote() throws IOException {
        bufferL.flip();
        int ret = remoteChannel.write(bufferL);
        XLog.d(TAG, "write2Remote size:"+ret);

    }


    private void close(String because){
        String log = "close tunnel work ["+remote.toString()+"]";
        if (!TextUtils.isEmpty(because))
            log += " cause by:"+because;
        Log.e(TAG, log);
        try {
            proxyChannel.close();
            remoteChannel.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
