package com.securityca.network;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class Connection {
    private final Socket socket;
    private final MessageManager messages;

    private Connection(Socket socket, MessageManager messages) {
        this.socket = socket;
        this.messages = messages;
    }

    public static Connection accept(ServerSocket server) throws IOException, GeneralSecurityException {
        return open(server.accept());
    }

    public void handleUntilDisconnect() {
        messages.handleIncoming();
    }

    public static Connection connect(String host, int port) throws IOException, GeneralSecurityException {
        return open(new Socket(host, port));
    }

    public void start(Runnable onDisconnect) {
        Thread.startVirtualThread(() -> {
            try {
                messages.handleIncoming();
            } finally {
                onDisconnect.run();
            }
        });
    }

    public void close() throws IOException { socket.close(); }

    public void send(String line) { messages.handleOutgoing(line); }

    private static Connection open(Socket socket) throws IOException, GeneralSecurityException {
        try {
            var in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            var out = new PrintWriter(socket.getOutputStream(), true);

            IO.println("Connected to " + socket.getInetAddress().getHostAddress() + ". Setting up encryption...");
            byte[] secret = handshake(in, out);

            return new Connection(socket, new MessageManager(secret, in, out));
        } catch (Exception e) {
            socket.close();
            throw e;
        }
    }

    private static byte[] handshake(BufferedReader in, PrintWriter out) throws IOException, GeneralSecurityException {
        // Source: https://mojoauth.com/security-guides/generate-keypair-using-x25519-with-java
        var kpg = KeyPairGenerator.getInstance("X25519");

        var pair = kpg.generateKeyPair();
        var publicDer = pair.getPublic().getEncoded(); // bytes in X.509 format

        // Send public key
        out.println(Base64.getEncoder().encodeToString(publicDer));

        // Receive their public key, decode from bytes in X.509 format while stripping PK identifier
        var theirLine = in.readLine();
        if (theirLine == null) throw new IOException("Peer hung up during handshake.");
        var theirPub = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(theirLine)));

        // Compute shared secret
        var ka = KeyAgreement.getInstance("X25519");
        ka.init(pair.getPrivate());
        ka.doPhase(theirPub, true);
        return ka.generateSecret();
    }
}
