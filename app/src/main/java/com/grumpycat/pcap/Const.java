package com.grumpycat.pcap;

/**
 * Created by cc.he on 2018/8/29
 */
public interface Const {
    int MTU = 2560;
    String VPN_IP4 = "10.8.0.2";
    int RANDOM_PORT = 0;

    int IP_ICMP_PROTOCOL =  1;
    int IP_TCP_PROTOCOL =   6;
    int IP_UDP_PROTOCOL =   17;

    /**
     * DNS Server
     */
    String GOOGLE_DNS_FIRST = "8.8.8.8";
    String GOOGLE_DNS_SECOND = "8.8.4.4";
    String AMERICA = "208.67.222.222";
    String HK_DNS_SECOND = "205.252.144.228";
    String CHINA_DNS_FIRST = "114.114.114.114";
}
