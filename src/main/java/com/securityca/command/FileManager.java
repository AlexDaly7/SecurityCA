package com.securityca.command;

import com.securityca.ClientState;
import com.securityca.FilePaths;
import com.securityca.crypto.CryptoUtils;
import com.securityca.manifest.ManifestManager;
import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileManager {
    public static CommandOutput readFile(String filename) {
        try {
            var file = Files.readAllBytes(Paths.get(filename));
            var nameBytes = filename.getBytes();

            byte[] data = ByteBuffer.allocate(2+nameBytes.length+file.length)
                    .putShort((short) nameBytes.length)
                    .put(nameBytes)
                    .put(file)
                    .array();

            String encrypted = CryptoUtils.encrypt(ClientState.getDecryptionKey(), data);

            IO.println("File has been read successfully!\nSending now...");

            // Manifest manager must be told to expect the coming acknowledgement from here
            // To pass the filename to be added to the manifest.
            ManifestManager.expectAck(filename);

            return CommandOutput.send(new Packet(PacketType.FILE, encrypted.getBytes(StandardCharsets.UTF_8)));
        } catch (IOException e) {
            return CommandOutput.error("Error reading file " + filename);
        }
    }


    public static boolean saveFile(byte[] fileData, String name) {
        Path path = Paths.get(FilePaths.SERVER_STORAGE.toString(), name);
        File file = new File(path.toUri());

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(fileData);
            IO.println("File saved from client");
            return true;
        } catch (FileNotFoundException e) {
            IO.println("The file could not be created: "+ e);
        } catch (IOException e) {
            IO.println("There was a problem saving the file: "+ e);
        }
        return false;
    }
}
