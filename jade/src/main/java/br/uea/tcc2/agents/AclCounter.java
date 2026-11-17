package br.uea.tcc2.agents;

import java.util.concurrent.atomic.AtomicLong;

import jade.lang.acl.ACLMessage;

/** Conta as mensagens FIPA-ACL trocadas entre os agentes locais (uma por destinatário). */
public final class AclCounter {
    private static final AtomicLong total = new AtomicLong();

    private AclCounter() {}

    public static void count(ACLMessage m) {
        int n = 0;
        java.util.Iterator<?> it = m.getAllReceiver();
        while (it.hasNext()) { it.next(); n++; }
        total.addAndGet(Math.max(1, n));
    }

    public static long get() { return total.get(); }

    public static void reset() { total.set(0); }
}
