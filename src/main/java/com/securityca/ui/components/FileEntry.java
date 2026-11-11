package com.securityca.ui.components;

import com.securityca.network.Connection;

import javax.swing.*;
import java.awt.*;

public class FileEntry extends JPanel {
    public FileEntry(Connection conn, String filename, String filehash) {
        super(new BorderLayout());

        add(new JLabel(filename),  BorderLayout.WEST);
        setToolTipText(filehash);

        var deleteButton = new JButton("Delete");
        add(deleteButton, BorderLayout.EAST);

        deleteButton.addActionListener(_ -> {
            conn.send("DELETE " + filehash);
        });

        setAlignmentX(LEFT_ALIGNMENT);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
