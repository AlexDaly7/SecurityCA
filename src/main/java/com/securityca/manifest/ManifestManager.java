package com.securityca.manifest;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityca.ClientState;
import com.securityca.FilePaths;
import com.securityca.crypto.CryptoUtils;

import java.io.IOException;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ManifestManager {
    private static List<FileEntry> entries = new ArrayList<>();
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String lastName;
    private static boolean expectingAck = false;

    private static boolean isLoaded = false;

    private static Runnable onChange = () -> {};

    private static byte[] salt;

    public static void setOnChange(Runnable r) {
        onChange = r;
    }

    public static boolean unlock(char[] password) throws IOException {
        boolean exists = Files.exists(FilePaths.CLIENT_MANIFEST);
        String packet = "";

        if (exists) {
            IO.println("Checking manifest");
            String[] parts = Files.readString(FilePaths.CLIENT_MANIFEST).split(" ", 2);
            if (parts.length != 2) throw new IOException("Manifest file is corrupt.");

            salt = Base64.getDecoder().decode(parts[0]);
            packet = parts[1];
        } else {
            IO.println("Creating new manifest");
            salt = new byte[16];
            new SecureRandom().nextBytes(salt);
        }

        ClientState.setDecryptionKey(CryptoUtils.keyFromPassword(password, salt));

        try {
            entries = exists ? deserialize(CryptoUtils.decrypt(ClientState.getDecryptionKey(), packet)) : new ArrayList<>();
        } catch (GeneralSecurityException e) {
            return false;
        }

        isLoaded = true;
        if (!exists) save();
        return true;
    }

    public static void save() throws IOException {
        if (!isLoaded) throw new IllegalStateException("Manifest not loaded, blocked saving blank manifest");

        String encrypted = CryptoUtils.encrypt(ClientState.getDecryptionKey(), serialize(entries));
        Path tmp = FilePaths.CLIENT_MANIFEST.resolveSibling("manifest.bin.tmp");
        Files.writeString(tmp, Base64.getEncoder().encodeToString(salt) + " " + encrypted);
        Files.move(tmp, FilePaths.CLIENT_MANIFEST, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public static byte[] serialize(List<FileEntry> entries) throws IOException {
        return MAPPER.writeValueAsBytes(entries);
    }

    public static List<FileEntry> deserialize(byte[] data) throws IOException {
        return MAPPER.readValue(data, new TypeReference<>() {});
    }

    public static void expectAck(String name) {
        lastName = name;
        expectingAck = true;
    }

    public static void disregardAck() {
        lastName = "";
        expectingAck = false;
    }

    public static void saveFile(String id) throws IOException {
        if (expectingAck) {
            entries.add(new FileEntry(id, lastName, System.currentTimeMillis()));
            save();
            onChange.run();
            lastName = "";
            expectingAck = false;
        }
    }

    public static List<FileEntry> getFiles() {
        return entries;
    }

    public static void deleteFile(String hex) throws IOException {
        for (int i=0;i<entries.size();i++) {
            if(entries.get(i).id().equals(hex)) {
                entries.remove(i);
                save();
                onChange.run();
                IO.println("The file "+hex+" was deleted.");
                return;
            }
        }

        IO.println("There was no object in the manifest by the id: "+hex);
    }

    public static String getName(String hex) {
        for (FileEntry entry : entries) {
            if (entry.id().equals(hex)) {
                return entry.name();
            }
        }

        return "Unnamed_File";
    }
}
