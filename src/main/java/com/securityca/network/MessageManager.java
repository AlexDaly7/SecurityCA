package com.securityca.network;

import com.securityca.ClientState;
import com.securityca.command.Command;
import com.securityca.command.CommandOutput;
import com.securityca.command.FileManager;
import com.securityca.crypto.CryptoUtils;
import com.securityca.manifest.ManifestManager;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;

public class MessageManager {
    private static final Map<String, Command> commands = Map.of(
            "FILE", args -> FileManager.readFile(args[0])
    );

    private final SecretKey key;

    private final BufferedReader in;
    private final PrintWriter out;

    public MessageManager(byte[] sharedSecret,  BufferedReader in, PrintWriter out) throws GeneralSecurityException {
        this.in = in;
        this.out = out;
        // "chat v1" is the label. This is so we can later use one secret for multiple keys to distinguish operations, say once we add file transfer/storage/accession, e.g. "files v1"
        // Turn into AES key. Done by first taking the raw secret, then "expanding" with our "chat v1" label and producing the 32byte AES key.
        this.key = CryptoUtils.aesFromSharedSecret(sharedSecret, "chat v1");
    }

    public void send(Packet packet) throws GeneralSecurityException {
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
                        case FILEACK -> {
                            ByteBuffer buffer = ByteBuffer.wrap(packet.data());
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
                                // Send confirmation to the client so they can save the HexFormat id.

                                byte[] status = "success".getBytes();
                                ByteBuffer buffer = ByteBuffer.allocate(64+status.length)
                                        .put(nameHex.getBytes())
                                        .put(status);
                                this.send(new Packet(PacketType.FILEACK, buffer.array()));
                                IO.println("File acknowledgement has been set.");
                            } else {
                                byte[] status = "error".getBytes();
                                byte[] hex = "x".repeat(64).getBytes(StandardCharsets.US_ASCII);
                                ByteBuffer buffer = ByteBuffer.allocate(64+status.length)
                                        .put(hex)
                                        .put(status);
                                this.send(new Packet(PacketType.FILEACK, buffer.array()));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            IO.println("Error:" + e);
        }
    }

    public void handleOutgoing(String line) throws GeneralSecurityException {
        var parts = line.split(" ");
        Command command = commands.get(parts[0]);

        if (command == null) {
            this.send(new Packet(PacketType.MESSAGE, line.getBytes(StandardCharsets.UTF_8)));
            return;
        }

        CommandOutput output = command.run(Arrays.copyOfRange(parts, 1, parts.length));

        if (output.success) {
            this.send(output.packet);
        } else {
            IO.println("Error: " + output);
        }
    }
}
