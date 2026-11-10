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

        try {
            Connection conn;
            if (isServer) {
                conn = Connection.listen(PORT);
            } else {
                LoginUI.show();
                conn = Connection.connect(args[0], PORT);
            }

            conn.start(() -> {
                IO.println("Disconnected.");
                System.exit(0);
            });

            IO.println("HELP for commands, Ctrl + D or Ctrl + Z on Windows to quit.");

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
