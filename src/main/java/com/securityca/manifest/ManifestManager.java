package com.securityca.manifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityca.ClientState;
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
    private static final Path DIR = Path.of(System.getProperty("user.home"), ".securityca");
    private static final Path PATH = DIR.resolve("manifest.bin");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static boolean loaded = false;

    // TODO: Make login and have manifestKey read from there.
    static SecretKey manifestKey = ClientState.getDecryptionKey();

    public static void checkManifest() throws IOException, GeneralSecurityException {
        Files.createDirectories(DIR);

        if(!Files.exists(PATH)) {
            IO.println("manifest.bin created.");
            entries = new ArrayList<>();
            loaded = true;
            save();
        } else {
            IO.println("manifest.bin already exists");
            load();
        }
    }

    public static void save() throws IOException, GeneralSecurityException {
        if(!loaded) throw new IllegalStateException("Manifest not loaded, blocked saving blank manifest");

        String encrypted = CryptoUtils.encrypt(manifestKey, serialize(entries));
        Path tmp = PATH.resolveSibling("manifest.bin.tmp");
        Files.writeString(tmp, encrypted);
        Files.move(tmp, PATH, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public static void load() throws IOException, GeneralSecurityException {
        String data = Files.readString(PATH);
        byte[] decrypted = CryptoUtils.decrypt(manifestKey, data);
        entries = deserialize(decrypted);
        loaded = true;
    }

    public static byte[] serialize(List<FileEntry> entries) throws JsonProcessingException {
        return MAPPER.writeValueAsBytes(entries);
    }

    public static List<FileEntry> deserialize(byte[] data) throws IOException {
        return MAPPER.readValue(data, new TypeReference<>() {});
    }

    public static void saveFile(String id, String name) throws GeneralSecurityException, IOException {
        entries.add(new FileEntry(id, name));
        save();
    }

    public static List<FileEntry> getFiles() {
        return entries;
    }
}
