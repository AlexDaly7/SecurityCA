package com.securityca;


import com.securityca.manifest.ManifestManager;
import com.securityca.network.MessageManager;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.net.*;
import java.nio.channels.IllegalBlockingModeException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import com.formdev.flatlaf.FlatLightLaf;
import com.securityca.ui.LoginUI;
import javax.swing.*;

public class Main {
    static void main(String[] args) throws Exception {
        FlatLightLaf.setup();
        FilePaths.setupFilePaths();

        int port = 5000;
        boolean isServer = args.length == 0;
        ClientState.setIsServer(isServer);

        // TODO: The personal key must be checked using manifest manager, and opportunity for user to retry.
        if (!isServer) {
            SwingUtilities.invokeLater(() -> {
                // Client should only connect after passkey is verified.
                LoginUI.show();
            });
        }

        // If we're connecting to a device (aka have an IP address arg), connect, otherwise listen
        try (var socket = isServer ? listen(port) : new Socket(args[0], port);
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

            IO.println("HELP for commands, Ctrl + D or Ctrl + Z on Windows to quit.");

            // Read until message arrives, then decrypt
            Thread.startVirtualThread(() -> {
                msgManager.handleIncoming();

                IO.println("Disconnected.");
                System.exit(0);
            });

            String line;
            while ((line = IO.readln()) != null) msgManager.handleOutgoing(line);
        } catch(IllegalArgumentException e){
            IO.println("Error, given illegal/inapropriate argument:" + e);
        } catch(NoSuchAlgorithmException e){
            IO.println("Error, cryptographic algorithm not available:" + e);
        } catch(NullPointerException e){
            IO.println("Error, null instead of valid object:" + e);
        } catch(InvalidKeyException e){
            IO.println("Error, Invalid key:" + e);
        } catch(IllegalStateException e){
            IO.println("Error, method called at illegal time:" + e);
        } catch(IOException e){
            IO.println("Error, IO Exception occurred:" + e);
        } catch(IOError e){
            IO.println("IO Error:" + e);
        }
    }

    private static Socket listen(int port) {
        try (var server = new ServerSocket(port)) {
            IO.print("Waiting for connection on port " + port + "...");
            return server.accept();
        } catch(IllegalArgumentException e){
            IO.println("Error, given illegal/inapropriate argument:" + e);
        } catch(SocketTimeoutException e){
            IO.println("Error, socket accept timeout:" + e);
        } catch(IllegalBlockingModeException e){
            IO.println("Error, unchecked exception on channel in incorrect blocking mode:" + e);
        } catch(IOException e){
            IO.println("Error, IO Exception occurred:" + e);
        }
        return null;
    }
}
