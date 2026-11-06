package com.securityca.command;

import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import java.io.*;
import java.nio.ByteBuffer;
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

            IO.println("File has been read successfully!\nSending now...");
            return new CommandOutput(new Packet(PacketType.FILE, data));
        } catch (IOException e) {
            return new CommandOutput("Error reading file " + filename);
        }
    }

    public static void saveFile(byte[] fileData, String name) {
        // TODO: This is extremely unsafe in practice and needs to have the path sanitised.
        Path path = Path.of("storage", name);
        File file = new File(path.toUri());

        try {
            OutputStream os = new FileOutputStream(file);

            os.write(fileData);

            IO.println("File was successfully decrypted and saved");

            // TODO: Currently os.close() is not called if an exception is thrown, ideally it should.
            os.close();
        } catch (FileNotFoundException e) {
            IO.println("The file could not be created: "+ e);
        } catch (IOException e) {
            IO.println("There was a problem saving the file: "+ e);
        }
    }
}
