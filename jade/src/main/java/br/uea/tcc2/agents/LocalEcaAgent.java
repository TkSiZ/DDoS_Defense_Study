package br.uea.tcc2.agents;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jade.core.Agent;
import jade.core.behaviours.CyclicBehaviour;
import org.json.JSONObject;

/**
 * Agente reativo (borda ou central). Só regras Evento-Condição-Ação:
 *   R1 ameaça no meu domínio          -> mitigar (drop se z >= 200, senão rate_limit) e alertar vizinhos
 *   R2 ameaça some e nenhum vizinho   -> restaurar e alertar vizinhos
 *   R3 vizinho alerta ameaça          -> rate_limit no meu domínio (pushback)
 *      (é assim que o pedido de bloqueio do central chega às bordas)
 *   R4 vizinho morre e sou o sucessor -> assumir o domínio dele (backup fixo em anel)
 *   R5 vizinho volta                  -> devolver o domínio
 */
public class LocalEcaAgent extends Agent implements PeerNetwork.Listener {

    private PeerNetwork net;
    private final Map<String, String> ownRule = new HashMap<>();
    private final Set<String> mitigating = new HashSet<>();
    private int tick = -1;

    private static String key(int d, String t) { return d + "|" + t; }
    private static int dom(String k) { return Integer.parseInt(k.substring(0, k.indexOf('|'))); }
    private static String tgt(String k) { return k.substring(k.indexOf('|') + 1); }

    @Override
    protected void setup() {
        net = new PeerNetwork(this, getArguments());
        net.start(this);
        addBehaviour(new Perception());
        System.out.println("[local-" + net.self + "] ECA pronto (" + net.role(net.self) + ").");
    }

    private class Perception extends CyclicBehaviour {
        public void action() {
            JSONObject frame = net.poll();
            if (frame == null) { block(20); return; }
            String type = frame.optString("type");
            int d = frame.getInt("domain");
            if (type.equals("reset")) {
                ownRule.clear(); mitigating.clear(); net.resetAlerts();
            } else if (type.equals("kill")) {
                if (d == net.self) { System.out.println("[local-" + d + "] encerrado (kill)"); myAgent.doDelete(); }
            } else if (type.equals("switch_state")) {
                net.handleSwitchState(frame, LocalEcaAgent.this);
            } else if (type.equals("features")) {
                tick = frame.optInt("tick", -1);
                onFeatures(d, frame.getJSONObject("f"));
            }
        }
    }

    private void onFeatures(int d, JSONObject f) {
        boolean threat = f.optBoolean("threat", false);
        String target = f.optString("target_ip", null);
        if (target != null && target.equals("null")) target = null;

        if (threat && target != null && !ownRule.containsKey(key(d, target))) {
            String s = f.optDouble("zscore", 0) >= 200 ? "drop" : "rate_limit";
            ownRule.put(key(d, target), s);
            net.alert(target, d, true, tick);
            mitigate(d, target, s, "local");
        }
        for (String k : new ArrayList<>(ownRule.keySet())) {
            if (dom(k) != d || (threat && tgt(k).equals(target))) continue;
            ownRule.remove(k);
            net.alert(tgt(k), d, false, tick);
        }
        for (String k : new ArrayList<>(mitigating)) {
            if (dom(k) == d && !ownRule.containsKey(k) && !net.anyPeerThreat(tgt(k))) restore(d, tgt(k));
        }
    }

    public void onPeerAlert(String target, int domain, boolean threat, int t) {
        for (int d : net.managed) {
            String k = key(d, target);
            if (threat) mitigate(d, target, "rate_limit", "peer");
            else if (!ownRule.containsKey(k) && !net.anyPeerThreat(target)) restore(d, target);
        }
    }

    public void onPeerDead(int peer) {
        if (net.successor(peer) == net.self) net.adopt(peer);
    }

    public void onPeerBorn(int peer) {
        if (!net.managed.contains(peer)) return;
        for (String k : new ArrayList<>(mitigating)) if (dom(k) == peer) restore(peer, tgt(k));
        for (String k : new ArrayList<>(ownRule.keySet()))
            if (dom(k) == peer) { ownRule.remove(k); net.alert(tgt(k), peer, false, tick); }
        net.managed.remove(peer);
    }

    public void onSwitchState(int domain, Set<String> targets) {
        for (String t : targets) mitigating.add(key(domain, t));
    }

    private void mitigate(int d, String target, String strategy, String cause) {
        if (mitigating.add(key(d, target))) net.decision("MITIGATE", target, d, strategy, tick, cause);
    }

    private void restore(int d, String target) {
        if (mitigating.remove(key(d, target))) net.decision("RESTORE", target, d, "", tick, "");
    }
}
