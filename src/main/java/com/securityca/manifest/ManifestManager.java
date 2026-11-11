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
import java.util.ArrayList;
import java.util.List;

public class ManifestManager {
    private static List<FileEntry> entries;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String lastName;
    private static boolean expectingAck = false;

    private static boolean isLoaded = false;

    public static boolean checkManifest() {
        if (!Files.exists(FilePaths.CLIENT_MANIFEST)) {
            IO.println("manifest.bin created.");
            entries = new ArrayList<>();
            isLoaded = true;
            save();

            return true;
        }

        return load();
    }

    public static void save() {
        try{
            if(!isLoaded) throw new IllegalStateException("Manifest not loaded, blocked saving blank manifest");

            String encrypted = CryptoUtils.encrypt(ClientState.getDecryptionKey(), serialize(entries));
            Path tmp = FilePaths.CLIENT_MANIFEST.resolveSibling("manifest.bin.tmp");
            Files.writeString(tmp, encrypted);
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

    public static boolean load() {
        try{
            String data = Files.readString(FilePaths.CLIENT_MANIFEST);
            byte[] decrypted = CryptoUtils.decrypt(ClientState.getDecryptionKey(), data);

            entries = deserialize(decrypted);
            isLoaded = true;

            return true;
        } catch(IOException e){
            IO.println("Error, IO Exception occurred:" + e);
            return false;
        } catch (RuntimeException e) {
            return false; // decryption failed
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
