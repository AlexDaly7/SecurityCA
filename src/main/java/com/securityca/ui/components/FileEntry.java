package com.securityca.ui.components;

import com.securityca.network.Connection;

import javax.swing.*;
import java.awt.*;

public class FileEntry extends JPanel {
    public FileEntry(Connection conn, String filename, String filehash) {
        super(new BorderLayout());

        add(new JLabel(filename),  BorderLayout.WEST);
        setToolTipText(filehash);

        JPanel buttons = new JPanel(new FlowLayout());

        var deleteButton = new JButton("Delete");
        buttons.add(deleteButton, BorderLayout.EAST);

        var requestButton = new JButton("Request");
        buttons.add(requestButton, BorderLayout.WEST);

        add(buttons, BorderLayout.EAST);

        deleteButton.addActionListener(_ -> {
            conn.send("DELETE " + filehash);
        });

        requestButton.addActionListener(_ -> {
            conn.send("FILEREQUEST " + filehash);
        });

        setAlignmentX(LEFT_ALIGNMENT);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
