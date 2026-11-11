package com.securityca;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FilePaths {
    private static final Path ROOT = Path.of(System.getProperty("user.home"), ".securityca");
    private static final Path SERVER = ROOT.resolve("server");
    private static final Path CLIENT = ROOT.resolve("client");

    public static final Path CLIENT_MANIFEST = CLIENT.resolve("manifest.bin");

    public static final Path SERVER_STORAGE = SERVER.resolve("storage");

    public static void setupFilePaths() {
        try {
            Files.createDirectories(ROOT);

            Files.createDirectories(SERVER);
            Files.createDirectories(SERVER_STORAGE);


            Files.createDirectories(CLIENT);
        } catch (IOException e) {
            IO.println("Error setting up file paths:" + e);
        }
    }
}
