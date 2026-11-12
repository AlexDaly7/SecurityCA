package com.securityca.network;

import com.securityca.ClientState;
import com.securityca.command.FileManager;
import com.securityca.crypto.CryptoUtils;
import com.securityca.manifest.ManifestManager;
import com.securityca.ui.Dialog;

import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class MessageManager {

    private final SecretKey key;

    private final BufferedReader in;
    private final PrintWriter out;

    public MessageManager(byte[] sharedSecret, String serverCode, BufferedReader in, PrintWriter out) throws IOException, GeneralSecurityException {
        this.in = in;
        this.out = out;
        // "chat v1" is the label. This is so we can later use one secret for multiple keys to distinguish operations, say once we add file transfer/storage/accession, e.g. "files v1"
        // Turn into AES key. Done by first taking the raw secret, then "expanding" with our "chat v1" label and producing the 32byte AES key.
        this.key = CryptoUtils.aesFromSharedSecret(sharedSecret, serverCode, "chat v1");

        String me = ClientState.isServer ? "server" : "client";
        String them = ClientState.isServer ? "client" : "server";
        out.println(CryptoUtils.encrypt(key, me.getBytes(StandardCharsets.UTF_8)));

        String line = in.readLine();
        if (line == null) throw new IOException("Peer hung up during key confirmation.");

        String reply = new String(CryptoUtils.decrypt(key, line), StandardCharsets.UTF_8);
        if (!reply.equals(them)) throw new IOException("Key confirmation failed.");
    }

    public void send(Packet packet) {
            out.println(CryptoUtils.encrypt(key, packet.toBytes()));
    }

    public void handleIncoming() {
        try {
            String line;
            Packet packet;
            while ((line = in.readLine()) != null) {
                packet = Packet.fromBytes(CryptoUtils.decrypt(key, line));
                if(!ClientState.isServer) {
                    // Client response
                    switch (packet.type()) {
                        case MESSAGE -> IO.println("> " + new String(packet.data(), StandardCharsets.UTF_8));
                        case FILE -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());

                            JFileChooser chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                            int result = chooser.showSaveDialog(null);

                            if(result == JFileChooser.APPROVE_OPTION) {

                                byte[] hexData = new byte[64];
                                buffer.get(hexData);
                                byte[] fileData = new byte[buffer.remaining()];
                                buffer.get(fileData);

                                String hex = new String(hexData, StandardCharsets.UTF_8);

                                try {
                                    byte[] unencrypted = CryptoUtils.decrypt(ClientState.getDecryptionKey(), new String(fileData, StandardCharsets.UTF_8));
                                    ByteBuffer fileBuffer = ByteBuffer.wrap(unencrypted);

                                    short nameLength = fileBuffer.getShort();
                                    byte[] name = new byte[nameLength];
                                    fileBuffer.get(name);

                                    byte[] unencryptedFile = new byte[fileBuffer.remaining()];
                                    fileBuffer.get(unencryptedFile);

                                    var isSaveSuccess = FileManager.saveFileWithPath(unencryptedFile, ManifestManager.getName(hex), chooser.getSelectedFile().toString());
                                    if (!isSaveSuccess) {
                                        Dialog.error("Could not save the file.");
                                    }
                                } catch (GeneralSecurityException e) {
                                    Dialog.error("This file is corrupt or is encrypted with a different passkey.");
                                }
                            }
                        }
                        case FILEACK -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());

                            if(buffer.remaining()==64) {
                                IO.println("There was a problem request the file from the server");
                            }

                            byte[] hashName = new byte[64];
                            buffer.get(hashName);
                            byte[] status = new byte[buffer.remaining()];
                            buffer.get(status);

                            if(new String(status).equals("success")) {
                                try {
                                    ManifestManager.saveFile(new String(hashName));
                                } catch (IOException e) {
                                    Dialog.error("Could not save to manifest");
                                }
                            } else if(new String(status).equals("error")) {
                                ManifestManager.disregardAck();
                                Dialog.error("The server could not store the file.");
                            }
                        }
                        case DELETEACK -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());
                            byte[] hexBytes = new byte[64];
                            buffer.get(hexBytes);
                            int status = buffer.get();

                            String hexString = new String(hexBytes, StandardCharsets.UTF_8);

                            if(status==1) {
                                try {
                                    ManifestManager.deleteFile(hexString);
                                } catch (IOException e) {
                                    Dialog.error("Could not save the manifest: " + e.getMessage());
                                }
                            } else {
                                Dialog.error("The server failed to delete the file: " + hexString);
                            }
                        }
                        default -> IO.println("Unknown receiving packet type: " + packet.type());
                    }

                } else {
                    // Server response
                    switch (packet.type()) {
                        case MESSAGE -> {}
                        case FILE -> {
                            var digest = MessageDigest.getInstance("SHA-256");
                            var hashName = digest.digest(packet.data());
                            String nameHex = HexFormat.of().formatHex(hashName);

                            if(FileManager.saveFile(packet.data(),  nameHex+ ".dat")) {
                                byte[] status = "success".getBytes();
                                ByteBuffer buffer = ByteBuffer.allocate(64+status.length)
                                        .put(nameHex.getBytes())
                                        .put(status);
                                this.send(new Packet(PacketType.FILEACK, buffer.array()));
                                IO.println("File acknowledgement has been set.");

                            } else {
                                byte[] status = "error".getBytes();
                                byte[] hex = "x".repeat(64).getBytes(StandardCharsets.UTF_8);
                                ByteBuffer buffer = ByteBuffer.allocate(64+status.length)
                                        .put(hex)
                                        .put(status);
                                this.send(new Packet(PacketType.FILEACK, buffer.array()));

                            }
                        }
                        case FILEREQUEST -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());
                            byte[] hexData = new byte[64];
                            buffer.get(hexData);
                            String hex = new String(hexData, StandardCharsets.UTF_8);

                            byte[] file = FileManager.getFile(hex);
                            buffer.clear();
                            buffer = ByteBuffer.allocate(64+file.length);
                            buffer.put(hexData);
                            buffer.put(file);
                            this.send(new Packet(PacketType.FILE, buffer.array()));

                        }
                        case DELETE -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());
                            byte[] hex = new byte[64];
                            buffer.get(hex);

                            byte[] data;
                            if(FileManager.deleteFile(new String(hex, StandardCharsets.UTF_8))) {
                                data = new byte[]{(byte) 1};
                            } else {
                                data = new byte[]{(byte) 0};
                            }
                            buffer = ByteBuffer.allocate(65)
                                    .put(hex)
                                    .put(data);

                            this.send(new Packet(PacketType.DELETEACK, buffer.array()));
                        }
                        default -> IO.println("Unhandled packet type: " + packet.type());
                    }
                }
            }
        } catch(IOException | GeneralSecurityException e){
            IO.println("Error, IO Exception occurred:" + e);
        }
    }
}
