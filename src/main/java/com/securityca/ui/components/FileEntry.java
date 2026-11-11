package com.securityca.ui.components;

import com.securityca.network.Connection;

import javax.swing.*;
import java.awt.*;

public class FileEntry extends JPanel {
    private final String filename;
    private final String filehash;

    public FileEntry(Connection conn, String filename, String filehash) {
        super(new BorderLayout());

        this.filename = filename;
        this.filehash = filehash;

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
