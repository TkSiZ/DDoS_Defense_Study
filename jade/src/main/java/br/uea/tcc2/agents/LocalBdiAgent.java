package br.uea.tcc2.agents;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import jade.core.behaviours.CyclicBehaviour;
import jade.domain.FIPANames;
import jade.lang.acl.ACLMessage;
import jade.proto.ContractNetInitiator;
import jade.proto.ContractNetResponder;
import org.json.JSONObject;

import bdi4jade.belief.Belief;
import bdi4jade.belief.TransientBelief;
import bdi4jade.core.SingleCapabilityAgent;
import bdi4jade.goal.Goal;
import bdi4jade.goal.GoalTemplateFactory;
import bdi4jade.plan.DefaultPlan;
import bdi4jade.plan.Plan;
import bdi4jade.plan.Plan.EndState;
import bdi4jade.plan.planbody.AbstractPlanBody;
import bdi4jade.reasoning.DefaultPlanSelectionStrategy;

/**
 * Agente BDI (BDI4JADE), na borda ou no central. Mantém uma crença de suspeita
 * local por (domínio, alvo), acumulada com decaimento; a confiança soma a essa
 * suspeita o apoio dos vizinhos que alertam o mesmo alvo. Confiança >= GOAL gera
 * o objetivo ProtectTarget e o motor escolhe o plano (drop, rate_limit ou
 * scrubbing). Quando um vizinho morre, o agente de menor id vivo abre um
 * Contract Net para decidir quem assume o domínio órfão; na arquitetura híbrida
 * segue a regra de sucessor fixo das bordas ECA.
 */
public class LocalBdiAgent extends SingleCapabilityAgent implements PeerNetwork.Listener {

    private static final long serialVersionUID = 1L;
    private static double envd(String k, double def) {
        try { String v = System.getenv(k); return v == null ? def : Double.parseDouble(v); }
        catch (Exception e) { return def; }
    }
    static final double DECAY = envd("BDI_DECAY", 0.7);
    static final double GOAL = envd("BDI_GOAL", 0.8);
    static final double RELEASE = envd("BDI_RELEASE", 0.4);
    static final double DROP_CONF = envd("BDI_DROP_CONF", 0.85);
    static final double PEER_W = envd("BDI_PEER", 0.3);
    private static final String P = "susp:";

    protected PeerNetwork net;
    private final Set<String> committed = new HashSet<>();
    private final Set<String> localAlert = new HashSet<>();
    private final Map<String, Boolean> overUsageOf = new HashMap<>();
    volatile int currentTick = -1;

    static String key(int d, String t) { return d + "|" + t; }
    static int dom(String k) { return Integer.parseInt(k.substring(0, k.indexOf('|'))); }
    static String tgt(String k) { return k.substring(k.indexOf('|') + 1); }

    public static class ProtectTarget implements Goal {
        private static final long serialVersionUID = 2L;
        final int domain; final String target; final double confidence; final boolean over; final String cause;
        public ProtectTarget(int d, String t, double c, boolean o, String why) {
            domain = d; target = t; confidence = c; over = o; cause = why;
        }
        public double getConfidence() { return confidence; }
        public boolean isOverUsage() { return over; }
    }
    public static class RestoreTarget implements Goal {
        private static final long serialVersionUID = 3L;
        final int domain; final String target;
        public RestoreTarget(int d, String t) { domain = d; target = t; }
    }
    public static class AdoptDomain implements Goal {
        private static final long serialVersionUID = 4L;
        final int domain;
        public AdoptDomain(int d) { domain = d; }
    }

    public abstract static class ProtectPlanBody extends AbstractPlanBody {
        protected abstract String strategy();
        public void action() {
            LocalBdiAgent a = (LocalBdiAgent) myAgent;
            ProtectTarget g = (ProtectTarget) getGoal();
            a.net.decision("MITIGATE", g.target, g.domain, strategy(), a.currentTick, g.cause);
            setEndState(EndState.SUCCESSFUL);
        }
    }
    public static class DropPlanBody extends ProtectPlanBody {
        private static final long serialVersionUID = 5L;
        protected String strategy() { return "drop"; }
    }
    public static class RateLimitPlanBody extends ProtectPlanBody {
        private static final long serialVersionUID = 6L;
        protected String strategy() { return "rate_limit"; }
    }
    public static class ScrubbingPlanBody extends ProtectPlanBody {
        private static final long serialVersionUID = 7L;
        protected String strategy() { return "scrubbing"; }
    }
    public static class RestorePlanBody extends AbstractPlanBody {
        private static final long serialVersionUID = 8L;
        public void action() {
            LocalBdiAgent a = (LocalBdiAgent) myAgent;
            RestoreTarget g = (RestoreTarget) getGoal();
            a.net.decision("RESTORE", g.target, g.domain, "", a.currentTick, "");
            setEndState(EndState.SUCCESSFUL);
        }
    }
    public static class NegotiateAdoptionPlanBody extends AbstractPlanBody {
        private static final long serialVersionUID = 9L;
        public void action() {
            ((LocalBdiAgent) myAgent).negotiateAdoption(((AdoptDomain) getGoal()).domain);
            setEndState(EndState.SUCCESSFUL);
        }
    }

    static class MitigationPlanSelection extends DefaultPlanSelectionStrategy {
        private static final long serialVersionUID = 10L;
        @Override
        public Plan selectPlan(Goal goal, Set<Plan> candidates) {
            if (goal instanceof ProtectTarget) {
                ProtectTarget g = (ProtectTarget) goal;
                String want;
                if (!g.isOverUsage()) want = "scrubbing";
                else if (g.getConfidence() >= DROP_CONF) want = "drop";
                else want = "rate_limit";
                for (Plan p : candidates)
                    if (want.equals(p.getId())) return p;
            }
            return super.selectPlan(goal, candidates);
        }
    }

    @Override
    protected void init() {
        net = new PeerNetwork(this, getArguments());

        getCapability().getPlanLibrary().addPlan(new DefaultPlan(
                "drop", GoalTemplateFactory.goalOfType(ProtectTarget.class), DropPlanBody.class));
        getCapability().getPlanLibrary().addPlan(new DefaultPlan(
                "rate_limit", GoalTemplateFactory.goalOfType(ProtectTarget.class), RateLimitPlanBody.class));
        getCapability().getPlanLibrary().addPlan(new DefaultPlan(
                "scrubbing", GoalTemplateFactory.goalOfType(ProtectTarget.class), ScrubbingPlanBody.class));
        getCapability().getPlanLibrary().addPlan(new DefaultPlan(
                "restore", GoalTemplateFactory.goalOfType(RestoreTarget.class), RestorePlanBody.class));
        getCapability().getPlanLibrary().addPlan(new DefaultPlan(
                "negotiate", GoalTemplateFactory.goalOfType(AdoptDomain.class), NegotiateAdoptionPlanBody.class));
        getCapability().setPlanSelectionStrategy(new MitigationPlanSelection());

        net.start(this);
        addBehaviour(new Perception());
        addBehaviour(new AdoptionResponder());
        System.out.println("[local-" + net.self + "] BDI pronto (" + net.role(net.self) + ").");
    }

    private Map<String, Double> suspicions() {
        Map<String, Double> s = new HashMap<>();
        for (Belief<?, ?> b : getCapability().getBeliefBase().getBeliefs()) {
            Object name = b.getName();
            if (name instanceof String && ((String) name).startsWith(P))
                s.put(((String) name).substring(P.length()), (Double) b.getValue());
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    private void setSuspicion(String k, double value) {
        Belief<?, ?> b = getCapability().getBeliefBase().getBelief(P + k);
        if (b == null)
            getCapability().getBeliefBase().addBelief(new TransientBelief<String, Object>(P + k, value));
        else ((Belief<String, Object>) b).setValue(value);
    }

    private double suspicion(String k) {
        Belief<?, ?> b = getCapability().getBeliefBase().getBelief(P + k);
        return b == null ? 0.0 : (Double) b.getValue();
    }

    private class Perception extends CyclicBehaviour {
        private static final long serialVersionUID = 11L;
        public void action() {
            JSONObject frame = net.poll();
            if (frame == null) { block(20); return; }
            String type = frame.optString("type");
            int d = frame.getInt("domain");
            if (type.equals("reset")) {
                for (String k : suspicions().keySet()) setSuspicion(k, 0.0);
                committed.clear(); localAlert.clear(); net.resetAlerts();
            } else if (type.equals("kill")) {
                if (d == net.self) { System.out.println("[local-" + d + "] encerrado (kill)"); myAgent.doDelete(); }
            } else if (type.equals("switch_state")) {
                net.handleSwitchState(frame, LocalBdiAgent.this);
            } else if (type.equals("features")) {
                currentTick = frame.optInt("tick", -1);
                onFeatures(d, frame.getJSONObject("f"));
            }
        }
    }

    private void onFeatures(int d, JSONObject f) {
        String target = f.optString("target_ip", null);
        if (target != null && target.equals("null")) target = null;

        Map<String, Double> susp = suspicions();
        for (Map.Entry<String, Double> e : susp.entrySet())
            if (dom(e.getKey()) == d) e.setValue(DECAY * e.getValue());
        if (target != null) {
            String k = key(d, target);
            susp.put(k, clamp01(susp.getOrDefault(k, 0.0) + evidence(f)));
            overUsageOf.put(k, f.optBoolean("over_usage", false));
        }
        for (Map.Entry<String, Double> e : susp.entrySet())
            if (dom(e.getKey()) == d) setSuspicion(e.getKey(), e.getValue());
        deliberate(d);
    }

    private void deliberate(int d) {
        Set<String> keys = new HashSet<>();
        for (String k : suspicions().keySet()) if (dom(k) == d) keys.add(k);
        for (String k : committed) if (dom(k) == d) keys.add(k);
        for (String t : net.peerTargets()) keys.add(key(d, t));
        for (String k : keys) {
            double local = suspicion(k);
            double conf = Math.min(1.0, local + PEER_W * net.support(tgt(k)));
            if (!localAlert.contains(k) && local >= GOAL) {
                localAlert.add(k);
                net.alert(tgt(k), d, true, currentTick);
            } else if (localAlert.contains(k) && local <= RELEASE) {
                localAlert.remove(k);
                net.alert(tgt(k), d, false, currentTick);
            }
            if (!committed.contains(k) && conf >= GOAL) {
                committed.add(k);
                addGoal(new ProtectTarget(d, tgt(k), conf, overUsageOf.getOrDefault(k, false),
                        local >= GOAL ? "local" : "peer"));
            } else if (committed.contains(k) && conf <= RELEASE) {
                committed.remove(k);
                addGoal(new RestoreTarget(d, tgt(k)));
            }
        }
    }

    public void onPeerAlert(String target, int domain, boolean threat, int t) {}

    public void onPeerDead(int peer) {
        if ("bdi".equals(net.arch)) {
            if (net.lowestAlive() == net.self) addGoal(new AdoptDomain(peer));
        } else if (net.successor(peer) == net.self) {
            net.adopt(peer);
        }
    }

    public void onPeerBorn(int peer) {
        if (!net.managed.contains(peer)) return;
        for (String k : new ArrayList<>(committed))
            if (dom(k) == peer) { committed.remove(k); net.decision("RESTORE", tgt(k), peer, "", currentTick, ""); }
        for (String k : new ArrayList<>(localAlert))
            if (dom(k) == peer) { localAlert.remove(k); net.alert(tgt(k), peer, false, currentTick); }
        for (String k : suspicions().keySet()) if (dom(k) == peer) setSuspicion(k, 0.0);
        net.managed.remove(peer);
    }

    public void onSwitchState(int domain, Set<String> targets) {
        for (String t : targets) {
            String k = key(domain, t);
            committed.add(k);
            setSuspicion(k, Math.max(suspicion(k), GOAL));
        }
    }

    void negotiateAdoption(final int orphan) {
        List<Integer> others = new ArrayList<>();
        for (int p : net.alive) if (p != net.self) others.add(p);
        if (others.isEmpty()) { net.adopt(orphan); return; }
        ACLMessage cfp = new ACLMessage(ACLMessage.CFP);
        cfp.setProtocol(FIPANames.InteractionProtocol.FIPA_CONTRACT_NET);
        cfp.setReplyByDate(new java.util.Date(System.currentTimeMillis() + 500));
        cfp.setContent(new JSONObject().put("domain", orphan).toString());
        for (int p : others) cfp.addReceiver(PeerNetwork.aid(p));
        AclCounter.count(cfp);
        addBehaviour(new ContractNetInitiator(this, cfp) {
            private static final long serialVersionUID = 13L;
            @SuppressWarnings({"rawtypes", "unchecked"})
            protected void handleAllResponses(Vector responses, Vector acceptances) {
                int best = net.self;
                int bestCost = net.managed.size() + (net.isCenter() ? 1 : 0);
                ACLMessage bestMsg = null;
                for (Object o : responses) {
                    ACLMessage r = (ACLMessage) o;
                    if (r.getPerformative() != ACLMessage.PROPOSE) continue;
                    JSONObject c = new JSONObject(r.getContent());
                    int cost = c.getInt("cost"), id = c.getInt("id");
                    if (cost < bestCost || (cost == bestCost && id < best)) { best = id; bestCost = cost; bestMsg = r; }
                }
                for (Object o : responses) {
                    ACLMessage r = (ACLMessage) o;
                    if (r.getPerformative() != ACLMessage.PROPOSE) continue;
                    ACLMessage reply = r.createReply();
                    reply.setPerformative(r == bestMsg ? ACLMessage.ACCEPT_PROPOSAL : ACLMessage.REJECT_PROPOSAL);
                    AclCounter.count(reply);
                    acceptances.add(reply);
                }
                if (bestMsg == null) net.adopt(orphan);
            }
        });
    }

    private class AdoptionResponder extends ContractNetResponder {
        private static final long serialVersionUID = 12L;
        AdoptionResponder() {
            super(LocalBdiAgent.this, createMessageTemplate(FIPANames.InteractionProtocol.FIPA_CONTRACT_NET));
        }
        protected ACLMessage handleCfp(ACLMessage cfp) {
            ACLMessage p = cfp.createReply();
            p.setPerformative(ACLMessage.PROPOSE);
            // custo: domínios já assumidos; o central só assume se não houver borda livre
            int cost = net.managed.size() + (net.isCenter() ? 1 : 0);
            p.setContent(new JSONObject().put("cost", cost).put("id", net.self).toString());
            AclCounter.count(p);
            return p;
        }
        protected ACLMessage handleAcceptProposal(ACLMessage cfp, ACLMessage propose, ACLMessage accept) {
            net.adopt(new JSONObject(cfp.getContent()).getInt("domain"));
            ACLMessage done = accept.createReply();
            done.setPerformative(ACLMessage.INFORM);
            AclCounter.count(done);
            return done;
        }
    }

    private double evidence(JSONObject f) {
        double e = 0.0;
        e += 0.22 * clamp01(f.optDouble("src_rise", 0) / 0.5);
        e += 0.13 * clamp01(f.optDouble("dst_drop", 0) / 0.5);
        e += 0.15 * clamp01(f.optDouble("zscore", 0) / 50.0);
        return e;
    }
    static double clamp01(double x) { return x < 0 ? 0 : (x > 1 ? 1 : x); }
}
