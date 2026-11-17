package br.uea.tcc2.agents;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/**
 * Servidor TCP (JSON Lines) que liga o substrato Python aos agentes.
 * Ver bridge/PROTOCOL.md.
 */
public class Bridge {
    private final int port;
    private volatile OutputStream out;
    private final Map<Integer, BlockingQueue<JSONObject>> inboxes = new ConcurrentHashMap<>();

    public Bridge(int port) { this.port = port; }

    public BlockingQueue<JSONObject> inbox(int domain) {
        return inboxes.computeIfAbsent(domain, k -> new LinkedBlockingQueue<>());
    }

    public JSONObject take(int domain, long millis) throws InterruptedException {
        return inbox(domain).poll(millis, TimeUnit.MILLISECONDS);
    }

    /** Bloqueia até o substrato conectar. */
    public void start() throws Exception {
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new java.net.InetSocketAddress("127.0.0.1", port));
        System.out.println("[bridge] escutando em 127.0.0.1:" + port + " ...");
        Socket sock = server.accept();
        this.out = sock.getOutputStream();
        System.out.println("[bridge] substrato conectado: " + sock.getRemoteSocketAddress());
        Thread reader = new Thread(() -> readLoop(sock), "bridge-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private void readLoop(Socket sock) {
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                JSONObject frame = new JSONObject(line);
                String type = frame.optString("type");
                if (type.equals("reset")) {
                    for (BlockingQueue<JSONObject> q : inboxes.values()) q.put(frame);
                } else if (type.equals("features") || type.equals("kill")
                        || type.equals("switch_state")) {
                    inbox(frame.optInt("domain", 0)).put(frame);
                } else if (type.equals("spawn")) {
                    inbox(-1).put(frame);
                }
            }
        } catch (Exception e) {
            System.out.println("[bridge] conexão encerrada: " + e.getMessage());
        }
    }

    public synchronized void send(JSONObject obj) {
        try {
            if (out != null) {
                out.write((obj.toString() + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (Exception e) {
            System.out.println("[bridge] falha ao enviar: " + e.getMessage());
        }
    }
}
