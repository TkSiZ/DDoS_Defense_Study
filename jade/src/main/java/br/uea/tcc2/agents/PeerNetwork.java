package br.uea.tcc2.agents;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import jade.core.AID;
import jade.core.Agent;
import jade.core.behaviours.CyclicBehaviour;
import jade.domain.introspection.AMSSubscriber;
import jade.domain.introspection.BornAgent;
import jade.domain.introspection.DeadAgent;
import jade.domain.introspection.Event;
import jade.domain.introspection.IntrospectionVocabulary;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;
import org.json.JSONObject;

/**
 * Parte comum dos agentes: domínios sob responsabilidade do agente, alertas
 * trocados com os vizinhos, vizinhos vivos (avisados pelo AMS do JADE) e envio
 * de decisões ao substrato. Não decide nada.
 *
 * Domínios 0..n-2 são switches de borda; o domínio n-1 é o switch central,
 * junto da vítima. MAS_COMMS=off desliga os alertas (ablação).
 */
public class PeerNetwork {

    public interface Listener {
        void onPeerAlert(String target, int domain, boolean threat, int tick);
        void onPeerDead(int peer);
        void onPeerBorn(int peer);
        void onSwitchState(int domain, Set<String> targets);
    }

    static final boolean COMMS = !"off".equalsIgnoreCase(System.getenv("MAS_COMMS"));

    private final Agent agent;
    private final Bridge bridge;
    public final int self;
    public final int n;
    public final int center;
    public final String arch;
    public final Set<Integer> alive = new TreeSet<>();
    public final Set<Integer> managed = new TreeSet<>();
    // alvo -> (domínio alertado -> agente que alertou)
    private final Map<String, Map<Integer, Integer>> peerThreat = new HashMap<>();
    private int rr = 0;

    public PeerNetwork(Agent agent, Object[] args) {
        this.agent = agent;
        this.bridge = (Bridge) args[0];
        this.self = (Integer) args[1];
        this.n = (Integer) args[2];
        this.arch = (String) args[3];
        this.center = n - 1;
        for (int d = 0; d < n; d++) alive.add(d);
        managed.add(self);
    }

    public void start(final Listener l) {
        agent.addBehaviour(new AMSSubscriber() {
            @SuppressWarnings({"unchecked", "rawtypes"})
            protected void installHandlers(Map handlers) {
                handlers.put(IntrospectionVocabulary.DEADAGENT, (EventHandler) (Event ev) -> {
                    int d = domainOf(((DeadAgent) ev).getAgent());
                    if (d < 0 || d == self || !alive.remove(d)) return;
                    for (Map<Integer, Integer> m : peerThreat.values()) m.values().removeIf(s -> s == d);
                    l.onPeerDead(d);
                });
                handlers.put(IntrospectionVocabulary.BORNAGENT, (EventHandler) (Event ev) -> {
                    int d = domainOf(((BornAgent) ev).getAgent());
                    if (d < 0 || d == self || !alive.add(d)) return;
                    // alertas sobre o domínio que voltou foram emitidos por quem o assumiu e ficaram velhos
                    for (Map<Integer, Integer> m : peerThreat.values()) m.remove(d);
                    l.onPeerBorn(d);
                });
            }
        });
        agent.addBehaviour(new CyclicBehaviour(agent) {
            private final MessageTemplate mt = MessageTemplate.MatchProtocol("alert");
            public void action() {
                ACLMessage m = myAgent.receive(mt);
                if (m == null) { block(); return; }
                JSONObject c = new JSONObject(m.getContent());
                String target = c.optString("target", null);
                int d = c.getInt("domain");
                boolean threat = c.getBoolean("threat");
                Map<Integer, Integer> by = peerThreat.computeIfAbsent(target, k -> new HashMap<>());
                if (threat) by.put(d, c.getInt("from")); else by.remove(d);
                l.onPeerAlert(target, d, threat, c.optInt("tick", -1));
            }
        });
    }

    private static int domainOf(AID aid) {
        String name = aid.getLocalName();
        if (!name.startsWith("local-")) return -1;
        try { return Integer.parseInt(name.substring(6)); } catch (NumberFormatException e) { return -1; }
    }

    public static AID aid(int d) { return new AID("local-" + d, AID.ISLOCALNAME); }

    /** Próximo quadro de qualquer domínio sob responsabilidade do agente, ou null. */
    public JSONObject poll() {
        Integer[] ds = managed.toArray(new Integer[0]);
        for (int i = 0; i < ds.length; i++) {
            int d = ds[(rr + i) % ds.length];
            JSONObject f = bridge.inbox(d).poll();
            if (f != null) {
                rr = (rr + i + 1) % ds.length;
                f.put("domain", d);
                return f;
            }
        }
        return null;
    }

    public boolean isCenter() { return self == center; }

    public String role(int d) { return d == center ? "central" : "borda"; }

    public void alert(String target, int domain, boolean threat, int tick) {
        if (!COMMS) return;
        ACLMessage m = new ACLMessage(ACLMessage.INFORM);
        m.setProtocol("alert");
        for (int p : alive) if (p != self) m.addReceiver(aid(p));
        if (!m.getAllReceiver().hasNext()) return;
        m.setContent(new JSONObject().put("target", target).put("domain", domain)
                .put("threat", threat).put("from", self).put("tick", tick).toString());
        AclCounter.count(m);
        agent.send(m);
    }

    /** Fração dos vizinhos (fora dos domínios deste agente) que alertam ameaça no alvo. */
    public double support(String target) {
        Map<Integer, Integer> by = peerThreat.get(target);
        if (by == null || n <= 1) return 0.0;
        int k = 0;
        for (int d : by.keySet()) if (!managed.contains(d)) k++;
        return Math.min(1.0, k / (double) (n - 1));
    }

    public boolean anyPeerThreat(String target) { return support(target) > 0; }

    public Set<String> peerTargets() { return peerThreat.keySet(); }

    /** Sucessor fixo: a próxima borda viva no anel (o central, se não houver bordas). */
    public int successor(int dead) {
        int edges = n - 1;
        int start = dead == center ? edges - 1 : dead;
        for (int i = 1; i <= edges; i++) {
            int c = (start + i) % edges;
            if (c != dead && alive.contains(c)) return c;
        }
        return alive.contains(center) && dead != center ? center : self;
    }

    public int lowestAlive() { return alive.isEmpty() ? self : alive.iterator().next(); }

    /** cause: "local" (detecção própria), "peer" (alerta de vizinho) ou "" (restauração). */
    public void decision(String action, String target, int domain, String strategy, int tick, String cause) {
        bridge.send(new JSONObject().put("type", "decision").put("ts_ms", System.currentTimeMillis())
                .put("tick", tick).put("domain", domain).put("agent", self)
                .put("target", target).put("action", action).put("strategy", strategy)
                .put("cause", cause));
    }

    public void adopt(int domain) {
        managed.add(domain);
        System.out.println("[local-" + self + "] assumiu o domínio " + domain + " (" + role(domain) + ")");
        bridge.send(new JSONObject().put("type", "telemetry").put("event", "adopted")
                .put("ts_ms", System.currentTimeMillis()).put("domain", domain).put("by", self)
                .put("acl_msgs", AclCounter.get()));
    }

    public void handleSwitchState(JSONObject frame, Listener l) {
        Set<String> ts = new TreeSet<>();
        for (Object o : frame.optJSONArray("targets") == null ? new org.json.JSONArray()
                : frame.getJSONArray("targets")) ts.add(o.toString());
        l.onSwitchState(frame.getInt("domain"), ts);
    }

    public void resetAlerts() { peerThreat.clear(); }
}
