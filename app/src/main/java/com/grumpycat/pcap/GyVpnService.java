package com.grumpycat.pcap;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

/**
 * Created by cc.he on 2018/8/28
 */
public class GyVpnService extends VpnService implements SocketProtector{

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public void onRevoke() {
        super.onRevoke();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        try {
            if (ipExchanger != null){
                ipExchanger.shutdown();
                ipExchanger = null;
            }else {
                establishVPN();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return super.onStartCommand(intent, flags, startId);
    }


    private IPExchanger ipExchanger;
    private void establishVPN(){
        Builder builder = new Builder();
        builder.setMtu(Const.MTU);
        builder.addAddress(Const.VPN_IP4, 32);
        builder.addRoute("0.0.0.0", 0);

        builder.addDnsServer(Const.HK_DNS_SECOND);
        builder.addDnsServer(Const.GOOGLE_DNS_FIRST);
        builder.addDnsServer(Const.CHINA_DNS_FIRST);
        builder.addDnsServer(Const.GOOGLE_DNS_SECOND);
        builder.addDnsServer(Const.AMERICA);

        ParcelFileDescriptor descriptor = builder.establish();

        ipExchanger = new IPExchanger(this);
        ipExchanger.startPacketCapture(descriptor);
    }



    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
    }
}
