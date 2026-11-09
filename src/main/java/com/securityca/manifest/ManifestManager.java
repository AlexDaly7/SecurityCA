package com.securityca.manifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityca.ClientState;
import com.securityca.FilePaths;
import com.securityca.crypto.CryptoUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public class ManifestManager {
    private static List<FileEntry> entries;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String lastName;
    private static boolean expectingAck = false;

    private static boolean isLoaded = false;

    // TODO: Make login and have manifestKey read from there.
    static SecretKey manifestKey = ClientState.getDecryptionKey();

    public static void checkManifest() throws IOException, GeneralSecurityException {
        if(!Files.exists(FilePaths.SERVER_MANIFEST)) {
            IO.println("manifest.bin created.");
            entries = new ArrayList<>();
            isLoaded = true;
            save();
        } else {
            IO.println("manifest.bin already exists");
            load();
        }
    }

    public static void save() throws IOException, GeneralSecurityException {
        if(!isLoaded) throw new IllegalStateException("Manifest not loaded, blocked saving blank manifest");

        String encrypted = CryptoUtils.encrypt(manifestKey, serialize(entries));
        Path tmp = FilePaths.SERVER_MANIFEST.resolveSibling("manifest.bin.tmp");
        Files.writeString(tmp, encrypted);
        Files.move(tmp, FilePaths.SERVER_MANIFEST, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public static void load() throws IOException, GeneralSecurityException {
        String data = Files.readString(FilePaths.SERVER_MANIFEST);
        byte[] decrypted = CryptoUtils.decrypt(manifestKey, data);
        entries = deserialize(decrypted);
        isLoaded = true;
    }

    public static byte[] serialize(List<FileEntry> entries) throws JsonProcessingException {
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

    public static void saveFile(String id) throws GeneralSecurityException, IOException {
        if(expectingAck) {
            entries.add(new FileEntry(id, lastName));
            save();
            lastName = "";
            expectingAck = false;
        }
    }

    public static List<FileEntry> getFiles() {
        return entries;
    }
}
