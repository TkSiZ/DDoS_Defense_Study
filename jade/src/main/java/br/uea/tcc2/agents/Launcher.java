package br.uea.tcc2.agents;

import jade.core.Profile;
import jade.core.ProfileImpl;
import jade.core.Runtime;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;
import org.json.JSONObject;

/**
 * --agent eca|bdi|hybrid  --edges N  --port P
 *
 * Sobe N agentes de borda (local-0..local-N-1) e um agente central (local-N):
 *   eca:    bordas ECA, central ECA
 *   bdi:    bordas BDI, central BDI
 *   hybrid: bordas ECA, central BDI
 *
 * Não há coordenador: os agentes conversam entre si. O Launcher só recria um
 * agente quando o substrato pede (quadro "spawn") e publica a contagem de
 * mensagens ACL a cada 500 ms.
 */
public class Launcher {

    static String classFor(String arch, int domain, int center) {
        boolean bdi = arch.equalsIgnoreCase("bdi") || (arch.equalsIgnoreCase("hybrid") && domain == center);
        return bdi ? "br.uea.tcc2.agents.LocalBdiAgent" : "br.uea.tcc2.agents.LocalEcaAgent";
    }

    public static void main(String[] args) throws Exception {
        String arch = "bdi";
        int edges = 3;
        int port = 7070;
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("--agent")) arch = args[i + 1].toLowerCase();
            if (args[i].equals("--edges") || args[i].equals("--domains")) edges = Integer.parseInt(args[i + 1]);
            if (args[i].equals("--port")) port = Integer.parseInt(args[i + 1]);
        }
        final String a = arch;
        final int n = edges + 1;
        final int center = edges;

        final Bridge bridge = new Bridge(port);
        bridge.inbox(-1);
        for (int d = 0; d < n; d++) bridge.inbox(d);

        Runtime rt = Runtime.instance();
        Profile profile = new ProfileImpl();
        profile.setParameter(Profile.MAIN_HOST, "localhost");
        profile.setParameter(Profile.GUI, "false");
        // porta própria e sem MTP para rodar 3 instâncias em paralelo
        profile.setParameter("port", String.valueOf(port + 1000));
        profile.setParameter("nomtp", "true");
        final ContainerController container = rt.createMainContainer(profile);

        for (int d = 0; d < n; d++) {
            AgentController ac = container.createNewAgent("local-" + d, classFor(a, d, center),
                    new Object[]{bridge, d, n, a});
            ac.start();
        }
        System.out.println("[launcher] arquitetura '" + a + "': " + edges + " bordas + 1 central"
                + (PeerNetwork.COMMS ? "" : " (comunicação desligada)") + ".");

        Thread control = new Thread(() -> {
            while (true) {
                try {
                    JSONObject f = bridge.take(-1, 500);
                    if (f == null) continue;
                    String type = f.optString("type");
                    if (type.equals("reset")) {
                        AclCounter.reset();
                    } else if (type.equals("spawn")) {
                        int d = f.getInt("domain");
                        container.createNewAgent("local-" + d, classFor(a, d, center),
                                new Object[]{bridge, d, n, a}).start();
                        System.out.println("[launcher] recriado local-" + d);
                    }
                } catch (Exception e) {
                    System.out.println("[launcher] controle: " + e.getMessage());
                }
            }
        }, "control");
        control.setDaemon(true);
        control.start();

        new java.util.Timer(true).scheduleAtFixedRate(new java.util.TimerTask() {
            public void run() {
                bridge.send(new JSONObject().put("type", "telemetry")
                        .put("ts_ms", System.currentTimeMillis()).put("acl_msgs", AclCounter.get()));
            }
        }, 500, 500);

        bridge.start();
    }
}
