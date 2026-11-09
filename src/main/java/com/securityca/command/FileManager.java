package com.securityca.command;

import com.securityca.ClientState;
import com.securityca.FilePaths;
import com.securityca.crypto.CryptoUtils;
import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

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
            return new CommandOutput(new Packet(PacketType.FILE, encrypted.getBytes(StandardCharsets.UTF_8)));
        } catch (IOException e) {
            return new CommandOutput("Error reading file " + filename, false);
        } catch (GeneralSecurityException e) {
            return new CommandOutput("Error encrypting file " + filename, false);
        }
    }

    public static void saveFile(byte[] fileData, String name) {
        Path path = Paths.get(FilePaths.SERVER_STORAGE.toString(), name);
        File file = new File(path.toUri());

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(fileData);
            IO.println("File saved from client");
        } catch (FileNotFoundException e) {
            IO.println("The file could not be created: "+ e);
        } catch (IOException e) {
            IO.println("There was a problem saving the file: "+ e);
        }
    }
}
