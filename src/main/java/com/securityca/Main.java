package com.securityca;

import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;

import com.formdev.flatlaf.FlatLightLaf;
import com.securityca.network.Connection;
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
            while (true) {
                IO.println("Waiting for new connection on port " + PORT + "...");

                try {
                    var conn = Connection.accept(server);

                    // finally ensures we still close cleanly even if en error occurs
                    try {
                        conn.handleUntilDisconnect();
                    } finally {
                        conn.close();
                    }

                    IO.println("Client disconnected.");
                } catch (GeneralSecurityException e) {
                    IO.println("Client connection failed: " + e.getMessage());
                } catch (RuntimeException e) {
                    IO.println("Client sent invalid data, closing connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            IO.println("Could not start sever: " + e.getMessage());
        }
    }

    private static void runClient(String serverIp) {
        try {
            Connection conn;

            LoginUI.show();
            conn = Connection.connect(serverIp, PORT);

            conn.start(() -> {
                IO.println("Disconnected.");
                System.exit(0);
            });

            IO.println("HELP for commands, Ctrl + C in terminal to quit.");

            String line;
            while ((line = IO.readln()) != null) conn.send(line);

            conn.close();
        } catch (IOException e) {
            IO.println("Connection failed: " +  e.getMessage());
        } catch (GeneralSecurityException e) {
            IO.println("Secure handshake failed: " + e.getMessage());
        }

    }
}
