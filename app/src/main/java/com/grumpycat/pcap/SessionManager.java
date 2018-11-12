package com.grumpycat.pcap;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by cc.he on 2018/8/30
 */
public class SessionManager {
    public static SessionManager getInstance(){
        return instance;
    }

    private static SessionManager instance = new SessionManager();

    private ConcurrentHashMap<Integer, ProxySession> sessions;
    private ConcurrentHashMap<Integer, ProxySession> udpSessions;
    private SessionManager(){
        sessions = new ConcurrentHashMap<>();
        udpSessions = new ConcurrentHashMap<>();
    }

    public ProxySession getSession(int key){
        return sessions.get(key);
    }

    public ProxySession putSession(int key, ProxySession session){
        return sessions.put(key, session);
    }

    public ProxySession remove(int key){
        return sessions.remove(key);
    }
}
