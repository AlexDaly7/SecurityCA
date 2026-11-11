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
import java.util.List;
import java.util.stream.Stream;

public class FileManager {
    public static CommandOutput readFile(String filename) {
        try {
            Path filePath = Paths.get(filename);
            var file = Files.readAllBytes(filePath);

            String name = filePath.getFileName().toString();
            var nameBytes = name.getBytes();

            byte[] data = ByteBuffer.allocate(2+nameBytes.length+file.length)
                    .putShort((short) nameBytes.length)
                    .put(nameBytes)
                    .put(file)
                    .array();

            String encrypted = CryptoUtils.encrypt(ClientState.getDecryptionKey(), data);

            IO.println("File has been read successfully!\nSending now...");

            // Manifest manager must be told to expect the coming acknowledgement from here
            // To pass the filename to be added to the manifest.
            ManifestManager.expectAck(name);

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

    public static boolean saveFileWithPath(byte[] fileData, String name, String strPath) {
        Path path = Path.of(strPath, name);
        File file = new File(path.toUri());

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(fileData);
            IO.println("File saved from server");
            return true;
        } catch (FileNotFoundException e) {
            IO.println("The file could not be created: "+ e);
        } catch (IOException e) {
            IO.println("There was a problem saving the file: "+ e);
        }
        return false;
    }

    // The two functions below are for the server only,
    // TODO: Consider moving these function to a separate files
    public static boolean deleteFile(String hex) {
        try {
            for (String existing : getFiles()) {
                if (existing.equals(hex)) {
                    return Files.deleteIfExists(FilePaths.SERVER_STORAGE.resolve(existing + ".dat"));
                }
            }
        } catch(IOException e) {
            IO.println("There was a problem deleting the file");
        }
        return false;
    }

    public static List<String> getFiles() {
        try(var stream = Files.list(FilePaths.SERVER_STORAGE)) {
            return stream
                    .map(p -> p.getFileName().toString())
                    .map(n -> n.substring(0, n.length()-4))
                    .toList();
        } catch (IOException e) {
            IO.println("Error getting file list.");
        }
        return List.of();
    }

    public static byte[] getFile(String hex) {
        try {
            List<Path> files = Files.list(FilePaths.SERVER_STORAGE).toList();

            for (Path file : files) {
                if (file.getFileName().toString().equals(hex + ".dat")) {
                    return Files.readAllBytes(file);
                }
            }
        } catch (IOException e) {
            IO.println("Error finding file");
        }
        return new byte[0];
    }


}
