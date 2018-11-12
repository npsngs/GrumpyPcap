package com.grumpycat.pcap;

import android.content.Intent;
import android.net.VpnService;
import android.os.Environment;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.forthe.xlog.XLog;
import com.grumpycat.pcap.tools.Messager;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class MainActivity extends AppCompatActivity
        implements View.OnClickListener, GrumpyPcap.OnVPNListener{
    private TextView tv_tcp_proxy,tv_log,tv_log2;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.btn_start).setOnClickListener(this);
        findViewById(R.id.btn_log).setOnClickListener(this);
        findViewById(R.id.btn_test_udp).setOnClickListener(this);
        findViewById(R.id.btn_test_tcp).setOnClickListener(this);
        findViewById(R.id.btn_test_api).setOnClickListener(this);
        tv_tcp_proxy = findViewById(R.id.tcp_proxy);
        tv_log = findViewById(R.id.tv_log);
        tv_log2 = findViewById(R.id.tv_log2);

        GrumpyPcap.getInstance().setOnVPNListener(this);
        GrumpyPcap.getInstance().setTcpThreadPoolMessager(new Messager() {
            @Override
            public void onMessage(final String msg) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        tv_log2.setText(msg);
                    }
                });
            }
        });
        XLog.init(this, Environment.getExternalStorageDirectory().getPath()+"/grumpypcap");
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.btn_start:
                Intent intent = VpnService.prepare(this);
                if (intent != null){
                    startActivityForResult(intent, 1024);
                }else{
                    startVpnService();
                }
                break;
            case R.id.btn_log:
                XLog.show(this);
                break;
            case R.id.btn_test_udp:
                startActivity(new Intent(this, NetTestActivity.class));
                break;
            case R.id.btn_test_tcp:
                startActivity(new Intent(this, TcpTestActivity.class));
                break;
            case R.id.btn_test_api:
                testApi();
                break;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 1024 && resultCode == RESULT_OK){
            startVpnService();
        }
    }

    private void startVpnService(){
        startService(new Intent(this, GyVpnService.class));
    }

    @Override
    public void onTcpProxyStarted(TCPProxy tcpProxy) {
        tv_tcp_proxy.setText(tcpProxy.toString());
    }

    private int count = 0;
    private void testApi(){
        tv_log.setText("...");
        new Thread(){
            @Override
            public void run() {
                final StringBuilder sb = new StringBuilder();
                try {
                    String urlStr = "http://192.168.17.38:8888/file";
                    sb.append(urlStr);
                    URL url = new URL(urlStr);
                    URLConnection rulConnection = url.openConnection();
                    HttpURLConnection httpUrlConnection = (HttpURLConnection) rulConnection;

                    sb.append("?count="+count).append("\n");
                    httpUrlConnection.setRequestProperty("count", count+"");
                    count++;
                    tv_log.post(new Runnable() {
                        @Override
                        public void run() {
                            tv_log.setText(sb.toString());
                        }
                    });

                    httpUrlConnection.connect();
                    int code = httpUrlConnection.getResponseCode();
                    sb.append(String.format("[code:%d] \n", code));
                    InputStream is = httpUrlConnection.getInputStream();
                    byte[] buffer = new byte[1024];
                    int ret;
                    while ((ret = is.read(buffer)) != -1){
                        sb.append(new String(buffer, 0, ret));
                    }
                    is.close();

                    httpUrlConnection.disconnect();


                } catch (Exception e) {
                    e.printStackTrace();
                    sb.append(e.getMessage());
                }finally {
                    tv_log.post(new Runnable() {
                        @Override
                        public void run() {
                            tv_log.setText(sb.toString());
                        }
                    });
                }
            }
        }.start();
    }
}
