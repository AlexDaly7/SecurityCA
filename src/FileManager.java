import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileManager {
    public static CommandOutput readFile(String filename) {
        try {
            var file = Files.readAllBytes(Paths.get(filename));
            return new CommandOutput(new Packet(PacketType.MESSAGE, file));
        } catch (IOException e) {
            return new CommandOutput("Error reading file " + filename);
        }
    }
}
