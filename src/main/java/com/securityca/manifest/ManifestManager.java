package com.securityca.manifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityca.ClientState;
import com.securityca.FilePaths;
import com.securityca.crypto.CryptoUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.*;
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

    public static boolean unlock(char[] password) {
        try {
            boolean exists = Files.exists(FilePaths.CLIENT_MANIFEST);
            String packet = "";

            if (exists) {
                IO.println("Checking manifest");
                String[] parts = Files.readString(FilePaths.CLIENT_MANIFEST).split(" ", 2);

                salt = Base64.getDecoder().decode(parts[0]);
                packet = parts[1];
            } else {
                IO.println("Creating new manifest");
                salt = new byte[16];
                new SecureRandom().nextBytes(salt);
            }

            ClientState.setDecryptionKey(CryptoUtils.keyFromPassword(password, salt));
            entries = exists ? deserialize(CryptoUtils.decrypt(ClientState.getDecryptionKey(), packet)) : new ArrayList<>();
            isLoaded = true;
            if (!exists) save();
            return true;
        } catch (IOException | RuntimeException _e) {
            return false;
        }
    }

    public static void save() {
        try{
            if(!isLoaded) throw new IllegalStateException("Manifest not loaded, blocked saving blank manifest");

            String encrypted = CryptoUtils.encrypt(ClientState.getDecryptionKey(), serialize(entries));
            Path tmp = FilePaths.CLIENT_MANIFEST.resolveSibling("manifest.bin.tmp");
            Files.writeString(tmp, Base64.getEncoder().encodeToString(salt) + " " + encrypted);
            Files.move(tmp, FilePaths.CLIENT_MANIFEST, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch(JsonProcessingException e) {
            IO.println("Error processing JSON(not just IO):" + e);
        } catch(InvalidPathException e) {
            IO.println("Error, Unchecked exception String cannot be converted to path):" + e);
        } catch(IllegalArgumentException e) {
            IO.println("Error, given illegal/inappropriate argument:" + e);
        } catch(UnsupportedOperationException e) {
            IO.println("Error, requested operation not supported:" + e);
        } catch(FileAlreadyExistsException e) {
            IO.println("Error, That file/directory already exists:" + e);
        } catch(DirectoryNotEmptyException e) {
            IO.println("Error, Directory not empty:" + e);
        } catch(IOException e) {
            IO.println("Error, IO Exception occurred:" + e);
        }
    }

    public static byte[] serialize(List<FileEntry> entries) {
        try{
            return MAPPER.writeValueAsBytes(entries);
        } catch(JsonProcessingException e){
            throw new RuntimeException("Error processing JSON(not just IO):", e);
        }
    }

    public static List<FileEntry> deserialize(byte[] data) {
        try {
            return MAPPER.readValue(data, new TypeReference<>() {
            });
        } catch(StreamReadException e){
            throw new RuntimeException("Error read-side streaming processing:", e);
        } catch(DatabindException e){
            throw new RuntimeException("Error databind level processing problem", e);
        } catch(IOException e){
            throw new RuntimeException("Error, IO Exception occurred:", e);
        }
    }

    public static void expectAck(String name) {
        lastName = name;
        expectingAck = true;
    }

    public static void disregardAck() {
        lastName = "";
        expectingAck = false;
    }

    public static void saveFile(String id) {
         try{
            if(expectingAck) {
                entries.add(new FileEntry(id, lastName));
                save();
                onChange.run();
                lastName = "";
                expectingAck = false;
            }
        } catch(UnsupportedOperationException e){
             IO.println("Error, add operation not supported by this list:" + e);
        } catch(ClassCastException e){
             IO.println("Error, class of element prevents adding it to the list:" + e);
        } catch(NullPointerException e){
             IO.println("Error, null instead of valid object:" + e);
        } catch(IllegalArgumentException e){
             IO.println("Error, given illegal/inappropriate argument:" + e);
        }
    }

    public static List<FileEntry> getFiles() {
        return entries;
    }

    public static boolean deleteFile(String hex) {
        for(int i=0;i<entries.size();i++) {
            if(entries.get(i).id().equals(hex)) {
                entries.remove(i);
                save();
                onChange.run();
                IO.println("The file "+hex+" was deleted.");
                return true;
            }
        }
        IO.println("There was no object in the manifest by the id: "+hex);
        return false;
    }

    public static String getName(String hex) {
        for(int i=0;i<entries.size();i++) {
            if(entries.get(i).id().equals(hex)) {
                return entries.get(i).name();
            }
        }
        return "Unnamed_File";
    }
}
