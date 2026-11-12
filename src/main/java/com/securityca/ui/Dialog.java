package com.securityca.ui;

import javax.swing.*;

public class Dialog {
    public static void error(String message) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(null, message, "Error", JOptionPane.ERROR_MESSAGE)
        );
    }
}
