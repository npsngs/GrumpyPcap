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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by cc.he on 2018/9/25
 */
public class TcpTestActivity extends Activity {
    private TextView tv1,tv2,tv3;
    private EditText et1,et2;
    private SharedPreferences sp;
    private int PORT= 9999;
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

        sp = getSharedPreferences("tcp_address", MODE_PRIVATE);
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
                    startServer();
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
                    sendToServer();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }.start();
    }

    private int recvCount;
    private void startServer() throws IOException {
        recvCount = 0;
        String log = String.format("[%s:%d]", Utils.ipIntToString(Utils.getLocalIP()), PORT);
        handler.obtainMessage(0,log).sendToTarget();
        byte[] buf = new byte[Const.MTU];
        server = new ServerSocket(PORT);
        while (true) {
            Socket socket = server.accept();
            InputStream is = socket.getInputStream();
            int ret;
            StringBuffer sb = new StringBuffer();
            while ((ret = is.read(buf)) != -1){
                sb.append(new String(buf, 0, ret));
            }
            String info = sb.toString();
            if (info.startsWith("Echo")){
                handler.obtainMessage(2,info).sendToTarget();
            }else {
                recvCount++;
                handler.obtainMessage(1,
                        String.format("接收到[%s:%d]的信息是：%s count:%d",
                                Utils.ipBytesToString(socket.getInetAddress().getAddress()),
                                socket.getPort(),
                                sb.toString(), recvCount))
                        .sendToTarget();


                String echo = String.format("Echo info:%s count:%d",info,  recvCount);
                String ip = et1.getEditableText().toString();
                remoteSocket = new Socket(ip, PORT);
                OutputStream os = remoteSocket.getOutputStream();
                os.write(echo.getBytes());
                os.flush();
                remoteSocket.close();
            }
        }
    }

    private ServerSocket server;
    private Socket remoteSocket;
    private void sendToServer() throws IOException {
        String ip = et1.getEditableText().toString();
        int port = Integer.valueOf(et2.getEditableText().toString());

        sp.edit().putInt("port",port).putString("ip",ip).apply();

        // 将数据打包-->打成数据报
        String info = "hello world!";


        remoteSocket = new Socket(ip, PORT);
        OutputStream os = remoteSocket.getOutputStream();
        os.write(info.getBytes());
        os.flush();
        remoteSocket.close();
    }



    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            server.close();
        }catch (Exception e){
            e.printStackTrace();
        }

        try {
            remoteSocket.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
