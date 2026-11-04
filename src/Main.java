
void main(String[] args) throws Exception {
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
        out.println("PK " + Base64.getEncoder().encodeToString(publicDer));

        // Receive their public key, decode from bytes in X.509 format while stripping PK identifier
        var theirLine = in.readLine();
        if (theirLine == null) throw new IOException("Peer hung up during handshake.");
        var theirPub = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(theirLine.substring(3))));

        // Compute shared secret
        var ka = KeyAgreement.getInstance("X25519");
        ka.init(pair.getPrivate());
        ka.doPhase(theirPub, true);
        var sharedSecret = ka.generateSecret();

        // "chat v1" is the label. This is so we can later use one secret for multiple keys to distinguish operations, say once we add file transfer/storage/accession, e.g. "files v1"
        // Turn into AES key. Done by first taking the raw secret, then "expanding" with our "chat v1" label and producing the 32bit AES key.
        var key = KDF.getInstance("HKDF-SHA256").deriveKey("AES", HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand("chat v1".getBytes(), 32));

        IO.println("Type messages, Ctrl + D or Ctrl + Z on Windows to quit.");

        // Read until message arrives, then decrypt
        Thread.startVirtualThread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    IO.println("> " + decrypt(key, line));
                }
            } catch (Exception e) {
                IO.println("Error:" + e);
            }

            IO.println("Disconnected.");
            System.exit(0);
        });

        String line;
        while ((line = IO.readln()) != null) out.println(encrypt(key, line));
    }
}

Socket listen(int port) throws IOException {
    try (var server = new ServerSocket(port)) {
        IO.print("Waiting for connection on port " + port + "...");
        return server.accept();
    }
}

String encrypt(SecretKey key, String msg) throws Exception {
    // Cryptographically secure random nonce per message as needed by AES-GCM
    var nonce = new byte[12];
    new SecureRandom().nextBytes(nonce);

    var cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));

    // Encrypt
    var ct = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
    var b64 = Base64.getEncoder();

    // Send encoded nonce and message
    return b64.encodeToString(nonce) + " " + b64.encodeToString(ct);
}


String decrypt(SecretKey key, String packet) throws Exception {
    // first elem is the b64 encoded nonce, 2nd elem is our the message
    var parts = packet.split(" ");
    var b64 = Base64.getDecoder();

    var cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, b64.decode(parts[0])));

    return new String(cipher.doFinal(b64.decode(parts[1])), StandardCharsets.UTF_8);
}