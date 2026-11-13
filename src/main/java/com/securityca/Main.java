package com.securityca;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.GeneralSecurityException;

import com.formdev.flatlaf.FlatLightLaf;
import com.securityca.crypto.CryptoUtils;
import com.securityca.network.Connection;
import com.securityca.ui.ChatWindow;
import com.securityca.ui.Dialog;
import com.securityca.ui.LoginUI;
import javax.swing.*;

public class Main {
    private static final int PORT = 5000;

    static void main(String[] args) {
        FlatLightLaf.setup();
        FilePaths.setupFilePaths();

        boolean isServer = args.length == 0;
        ClientState.setIsServer(isServer);

        if (isServer) {
            runServer();
        } else {
            runClient(args[0]);
        }
    }

    private static void runServer() {
        try (var server = new ServerSocket(PORT)) {

            String serverPassword;
            if (Files.exists(FilePaths.SERVER_PASSWORD)) {
                serverPassword = Files.readString(FilePaths.SERVER_PASSWORD).trim();
            } else {
                serverPassword = IO.readln("Set server password: ").trim();
                Files.writeString(FilePaths.SERVER_PASSWORD, serverPassword);
            }

            IO.println("Server password: " + serverPassword);
            String serverCode = CryptoUtils.stretchServerPassword(serverPassword);

            IO.println("Listening on port " + PORT + "...");
            while (true) {

                var socket = server.accept();
                var client = socket.getRemoteSocketAddress();
                Thread.startVirtualThread(() -> {
                    try (socket) {
                        Connection.open(socket, serverCode).handleUntilDisconnect();
                        IO.println(client + " disconnected.");
                    } catch (GeneralSecurityException e) {
                        IO.println(client + " failed handshake (wrong server password?): " + e.getMessage());
                    } catch (RuntimeException e) {
                        IO.println(client + " sent invalid data, closing connection: " + e.getMessage());
                    } catch (IOException e) {
                        IO.println(client + " connection error: " + e.getMessage());
                    }
                });
            }
        } catch (IOException e) {
            IO.println("Server stopped: " + e.getMessage());
        }
    }

    private static void runClient(String serverIp) {
        try {
            Connection conn = null;

            LoginUI.show();

            String prompt = "Server password:";
            while (conn == null) {
                String serverPassword = JOptionPane.showInputDialog(prompt);
                if (serverPassword == null) return;
                try {
                    conn = Connection.connect(serverIp, PORT, CryptoUtils.stretchServerPassword(serverPassword));
                } catch (GeneralSecurityException e) {
                    prompt = "Wrong server password, try again:";
                }
            }

            conn.start(() -> {
                JOptionPane.showMessageDialog(null, "Disconnected from server.");
                System.exit(0);
            });

            ChatWindow.show(conn);
        } catch (IOException e) {
            Dialog.error("Connection failed: " + e.getMessage());
        }
    }
}
