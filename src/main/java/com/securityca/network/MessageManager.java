package com.securityca.network;

import com.securityca.ClientState;
import com.securityca.command.Command;
import com.securityca.command.CommandOutput;
import com.securityca.command.FileManager;
import com.securityca.crypto.CryptoUtils;
import com.securityca.manifest.ManifestManager;

import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.PatternSyntaxException;

public class MessageManager {

    private final SecretKey key;

    private final BufferedReader in;
    private final PrintWriter out;

    public MessageManager(byte[] sharedSecret,  BufferedReader in, PrintWriter out) {
            this.in = in;
            this.out = out;
            // "chat v1" is the label. This is so we can later use one secret for multiple keys to distinguish operations, say once we add file transfer/storage/accession, e.g. "files v1"
            // Turn into AES key. Done by first taking the raw secret, then "expanding" with our "chat v1" label and producing the 32byte AES key.
            this.key = CryptoUtils.aesFromSharedSecret(sharedSecret, "chat v1");
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

                                byte[] unencrypted = CryptoUtils.decrypt(ClientState.getDecryptionKey(), new String(fileData, StandardCharsets.UTF_8));
                                ByteBuffer fileBuffer = ByteBuffer.wrap(unencrypted);

                                short nameLength = fileBuffer.getShort();
                                byte[] name = new byte[nameLength];
                                fileBuffer.get(name);

                                byte[] unencryptedFile = new byte[fileBuffer.remaining()];
                                fileBuffer.get(unencryptedFile);

                                FileManager.saveFileWithPath(unencryptedFile, ManifestManager.getName(hex), chooser.getSelectedFile().toString());
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
                                IO.println("ACK SUCCESS");
                                ManifestManager.saveFile(new String(hashName));
                            } else if(new String(status).equals("error")) {
                                ManifestManager.disregardAck();
                                IO.println("ACK ERROR");
                            }
                        }
                        case DELETEACK -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());
                            byte[] hexBytes = new byte[64];
                            buffer.get(hexBytes);
                            int status = buffer.get();

                            String hexString = new String(hexBytes, StandardCharsets.UTF_8);

                            if(status==1) {
                                ManifestManager.deleteFile(hexString);
                            } else {
                                IO.println("The server failed to delete the file: "+hexString);
                            }
                        }
                        default ->  IO.println("Unknown receiving packet type: " + packet.type());
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
                    }
                }
            }
        } catch(IOException e){
            IO.println("Error, IO Exception occurred:" + e);
        } catch(ReadOnlyBufferException e) {
            IO.println("Error, Unchecked exception content-mutation method invoked upon read-only buffer:" + e);
        } catch(UnsupportedOperationException e) {
            IO.println("Error, requested operation not supported:" + e);
        } catch(BufferOverflowException e) {
            IO.println("Error, Unchecked exception put operation reached target buffer's limit:" + e);
        } catch(IllegalArgumentException e) {
            IO.println("Error, given illegal/inapropriate argument:" + e);
        } catch(NoSuchAlgorithmException e) {
            IO.println("Error, cryptographic algorithm not available:" + e);
        } catch(NullPointerException e) {
            IO.println("Error, null instead of valid object:" + e);
        }
    }

    public void handleOutgoing(String line) {
        try{
            var parts = line.split(" ", 2);

            Command command = Arrays.stream(Command.values())
                    .filter(c -> c.name().equals(parts[0]))
                    .findFirst().orElse(null);

            if (command == null) {
                this.send(new Packet(PacketType.MESSAGE, line.getBytes(StandardCharsets.UTF_8)));
                return;
            }

            CommandOutput output = command.run(Arrays.copyOfRange(parts, 1, parts.length));

            if (!output.success) {
                IO.println("Error: " + output.message);
                return;
            }

            // Commands may print something locally, send a packet, or both
            if (output.message != null) IO.println(output.message);
            if (output.packet != null) this.send(output.packet);
        } catch(PatternSyntaxException e){
            IO.println("Error, unchecked exception in regular-expression pattern:" + e);
        } catch(ClassCastException e){
            IO.println("Error, attempted to cast to a subclass which is not an instance of:" + e);
        } catch(NullPointerException e){
            IO.println("Error, null instead of valid object:" + e);
        }  catch(ArrayIndexOutOfBoundsException e){
            IO.println("Error, index out of scope of array:" + e);
        } catch(IllegalArgumentException e){
            IO.println("Error, given illegal/inapropriate argument:" + e);
        }
    }
}
