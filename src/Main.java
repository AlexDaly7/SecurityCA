import com.formdev.flatlaf.FlatLightLaf;

import javax.swing.*;


void main(String[] args) throws Exception {
    FlatLightLaf.setup();

    // TEMP: show the GUI and skip the networking code below
    SwingUtilities.invokeLater(() -> StartupWindow.show());
    if (true) return;

    int port = 5000;

    // If we're connecting to a device (aka have an IP address arg), connect, otherwise listen
    try (var socket = args.length == 0 ? listen(port) : new Socket(args[0], port);
        var in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        var out = new PrintWriter(socket.getOutputStream(), true)) {

        IO.println("Connected to " + socket.getInetAddress().getHostAddress() + ". Setting up encryption...");

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
        byte[] sharedSecret = ka.generateSecret();

        MessageManager msgManager = new MessageManager(sharedSecret, in, out);

        IO.println("Type messages, Ctrl + D or Ctrl + Z on Windows to quit.");

        // Read until message arrives, then decrypt
        Thread.startVirtualThread(() -> {
            msgManager.handleIncoming();

            IO.println("Disconnected.");
            System.exit(0);
        });

        String line;
        while ((line = IO.readln()) != null) msgManager.handleOutgoing(line);
    } catch(SocketException e){
        IO.println("Error failed connection:" + e);
    }
}

Socket listen(int port) throws IOException {
    try (var server = new ServerSocket(port)) {
        IO.print("Waiting for connection on port " + port + "...");
        return server.accept();
    }
}
