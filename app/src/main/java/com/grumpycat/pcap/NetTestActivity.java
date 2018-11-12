package com.grumpycat.pcap;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.annotation.Nullable;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Created by cc.he on 2018/9/25
 */
public class NetTestActivity extends Activity {
    private TextView tv1,tv2,tv3;
    private EditText et1,et2;
    private SharedPreferences sp;
    @SuppressLint("HandlerLeak")
    private Handler handler = new Handler(){
        @Override
        public void handleMessage(Message msg) {
            if (msg.obj instanceof String){
                switch (msg.what){
                    case 0:
                        tv1.setText((String)msg.obj);
                        break;
                    case 1:
                        tv2.setText((String)msg.obj);
                        break;
                    case 2:
                        tv3.setText((String)msg.obj);
                        break;
                }
            }
        }
    };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_net);
        findViewById(R.id.btn_start_udpser).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                asyncStartUdpServer();
            }
        });

        findViewById(R.id.btn_send_udp_pk).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                asyncSendPackToServer();
            }
        });

        tv1 = findViewById(R.id.tv1);
        tv2 = findViewById(R.id.tv2);
        tv3 = findViewById(R.id.tv3);
        et1 = findViewById(R.id.et_ip);
        et2 = findViewById(R.id.et_port);

        sp = getSharedPreferences("address", MODE_PRIVATE);
        String ip = sp.getString("ip", "");
        int port = sp.getInt("port",0);
        et1.setText(ip);
        et2.setText(String.valueOf(port));
    }


    private void asyncStartUdpServer(){
        new Thread(){
            @Override
            public void run() {
                try {
                    startUdpServer();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private void asyncSendPackToServer(){
        new Thread(){
            @Override
            public void run() {
                try {
                    sendPackToServer();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private int recvCount;
    private void startUdpServer() throws IOException {
        recvCount = 0;
        String log = String.format("[%s:%d]", Utils.ipIntToString(Utils.getLocalIP()), 3333);
        handler.obtainMessage(0,log).sendToTarget();

        DatagramPacket dp;
        byte[] buf = new byte[1024];

        ds = new DatagramSocket(3333);
        dp = new DatagramPacket(buf, 1024);

        // 接收数据，放入数据报
        do {
            ds.receive(dp);
            // 从数据报中取出数据
            String info = new String(dp.getData(),0, dp.getLength());
            if (info.startsWith("Echo")){
                handler.obtainMessage(2,info).sendToTarget();
            }else{
                recvCount++;
                handler.obtainMessage(1,
                        String.format("接收到[%s:%d]的信息是：%s count:%d",
                                Utils.ipBytesToString(dp.getAddress().getAddress()),
                                dp.getPort(),
                                info,recvCount))
                        .sendToTarget();

                String echo = String.format("Echo info:%s count:%d",info,  recvCount);
                ds.send(new DatagramPacket(
                        echo.getBytes(),
                        echo.length(),
                        dp.getAddress(),
                        dp.getPort()));
            }
        } while (dp.getLength() != -1);
    }

    DatagramSocket ds;
    DatagramSocket sds;
    private void sendPackToServer() throws IOException {
        String ip = et1.getEditableText().toString();
        int port = Integer.valueOf(et2.getEditableText().toString());

        sp.edit().putInt("port",port).putString("ip",ip).apply();
        DatagramPacket dp;

        // 将数据打包-->打成数据报
        String info = "hello world!";

        byte[] ips = Utils.ipStringToByte(ip);

        String ipb = Utils.ipBytesToString(ips);
        Utils.assertTrue(ipb.equals(ip));
        dp = new DatagramPacket(
                info.getBytes(),
                info.length(),
                InetAddress.getByAddress(ips),
                3333);

        // 发出数据报
        ds.send(dp);
    }





    @Override
    protected void onDestroy() {
        super.onDestroy();
        try{
            ds.close();
        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            sds.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
