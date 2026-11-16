package edu.uta.cse4382.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Minimal "order intake" service used as the target for SpotBugs / FindSecBugs.
 *
 * Endpoints:
 *   POST /order          - VULNERABLE: deserializes request body with default XStream (CWE-502)
 *   GET  /import?file=.. - VULNERABLE: loads XML from a user-supplied path (CWE-22) and deserializes it (CWE-502)
 *   POST /order-safe     - FIXED: XStream locked down with an explicit type allow-list
 *
 * FOR CLASSROOM ANALYSIS ONLY. Do not expose this server to a network.
 */
public class OrderServer {

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/order", OrderServer::handleOrderVulnerable);
        server.createContext("/import", OrderServer::handleImportVulnerable);
        server.createContext("/order-safe", OrderServer::handleOrderSafe);
        server.start();
        System.out.println("Order service listening on http://127.0.0.1:8080");
    }

    // ---------------------------------------------------------------------
    // VULNERABLE #1 - Deserialization of untrusted data (CWE-502)
    // A default XStream 1.4.17 instance relies on a blocklist, so an attacker
    // can send a gadget-chain payload instead of an <order> (e.g. CVE-2021-39144).
    // ---------------------------------------------------------------------
    static void handleOrderVulnerable(HttpExchange ex) throws IOException {
        String body = readBody(ex);
        XStream xstream = new XStream();
        xstream.alias("order", Order.class);
        Object obj = xstream.fromXML(body);              // tainted input -> deserialization sink
        respond(ex, 200, "Received: " + obj);
    }

    // ---------------------------------------------------------------------
    // VULNERABLE #2 - Path traversal (CWE-22) feeding deserialization (CWE-502)
    // The "file" query parameter is used directly as a filesystem path.
    // ---------------------------------------------------------------------
    static void handleImportVulnerable(HttpExchange ex) throws IOException {
        String query = ex.getRequestURI().getQuery();
        String fileName = (query != null && query.startsWith("file="))
                ? URLDecoder.decode(query.substring(5), StandardCharsets.UTF_8)
                : "orders.xml";

        File f = new File("imports", fileName);          // no canonicalization / containment check
        XStream xstream = new XStream();
        xstream.alias("order", Order.class);
        try (InputStream in = new FileInputStream(f)) {
            Object obj = xstream.fromXML(in);
            respond(ex, 200, "Imported: " + obj);
        } catch (IOException e) {
            respond(ex, 404, "Could not read " + f.getPath()); // also leaks internal path
        }
    }

    // ---------------------------------------------------------------------
    // FIXED - explicit allow-list (the remediation the report recommends)
    // ---------------------------------------------------------------------
    static void handleOrderSafe(HttpExchange ex) throws IOException {
        String body = readBody(ex);
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);           // deny everything...
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypes(new Class[] { Order.class, String.class }); // ...then allow only what we expect
        xstream.alias("order", Order.class);
        try {
            Order order = (Order) xstream.fromXML(body);
            respond(ex, 200, "Received: " + order);
        } catch (RuntimeException e) {
            respond(ex, 400, "Rejected input");
        }
    }

    // ---------------------------------------------------------------------
    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void respond(HttpExchange ex, int status, String msg) throws IOException {
        byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
