package com.securityca.ui.components;

import com.securityca.network.Connection;
import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;

public class FileEntry extends JPanel {
    public FileEntry(Connection conn, String filename, String filehash) {
        super(new BorderLayout());

        add(new JLabel(filename),  BorderLayout.WEST);
        setToolTipText(filehash);

        JPanel buttons = new JPanel(new FlowLayout());

        var deleteButton = new JButton("Delete");
        buttons.add(deleteButton, BorderLayout.EAST);

        var requestButton = new JButton("Download");
        buttons.add(requestButton, BorderLayout.WEST);

        add(buttons, BorderLayout.EAST);

        deleteButton.addActionListener(_ ->
                conn.send(new Packet(PacketType.DELETE, filehash.getBytes(StandardCharsets.UTF_8)))
        );

        requestButton.addActionListener(_ ->
            conn.send(new Packet(PacketType.FILEREQUEST, filehash.getBytes(StandardCharsets.UTF_8)))
        );

        setAlignmentX(LEFT_ALIGNMENT);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
