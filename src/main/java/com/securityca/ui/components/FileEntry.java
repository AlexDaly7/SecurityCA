package com.securityca.ui.components;

import com.securityca.network.Connection;
import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class FileEntry extends JPanel {
    public FileEntry(Connection conn, String filename, String filehash, long uploadedAt) {
        super(new BorderLayout());

        var nameLabel = new JLabel(filename);
        add(nameLabel, BorderLayout.WEST);

        String date = uploadedAt == 0
                ? "Unknown upload date"
                : DateTimeFormatter.ofPattern("HH:mm dd/MM/yyyy")
                .format(Instant.ofEpochMilli(uploadedAt).atZone(ZoneId.systemDefault()));;

        setToolTipText("Uploaded: " + date + ", hash: " + filehash);

        var dateLabel = new JLabel(date);
        dateLabel.setFont(new Font(dateLabel.getFont().getName(), Font.PLAIN, 12));
        add(dateLabel, BorderLayout.SOUTH);

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
