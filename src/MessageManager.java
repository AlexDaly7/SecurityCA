import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Map;

public class MessageManager {
    private static final Map<String, Command> commands = Map.of(
            "FILE", args -> FileManager.readFile(args[0])
    );

    private final SecretKey key;

    private final BufferedReader in;
    private final PrintWriter out;

    public MessageManager(byte[] sharedSecret,  BufferedReader in, PrintWriter out) throws GeneralSecurityException {
        this.in = in;
        this.out = out;
        // "chat v1" is the label. This is so we can later use one secret for multiple keys to distinguish operations, say once we add file transfer/storage/accession, e.g. "files v1"
        // Turn into AES key. Done by first taking the raw secret, then "expanding" with our "chat v1" label and producing the 32byte AES key.
        this.key = KDF.getInstance("HKDF-SHA256").deriveKey("AES", HKDFParameterSpec.ofExtract().addIKM(sharedSecret).thenExpand("chat v1".getBytes(), 32));
    }

    public void send(Packet packet) throws GeneralSecurityException {
        out.println(CryptoUtils.encrypt(key, packet.toBytes()));
    }

    public void handleIncoming() {
        try {
            String line;
            Packet packet;
            while ((line = in.readLine()) != null) {
                packet = Packet.fromBytes(CryptoUtils.decrypt(key, line));

                switch (packet.type()) {
                    case MESSAGE -> IO.println("> " + new String(packet.data(), StandardCharsets.UTF_8));
                    case FILE -> {
                        // TODO: ALEX FIX THIS AND MAKE IT SAVE TO A FOLDER LOCALLY !!!
                        // also rn you just get raw bytes so add byte headers indicating filename
                        // also also only save filename not full path or else you create an RCE
                    }
                    default ->  IO.println("Unknown receiving packet type: " + packet.type());
                }
            }
        } catch (Exception e) {
            IO.println("Error:" + e);
        }
    }

    public void handleOutgoing(String line) throws GeneralSecurityException {
        var parts = line.split(" ");
        Command command = commands.get(parts[0]);

        if (command == null) {
            this.send(new Packet(PacketType.MESSAGE, line.getBytes(StandardCharsets.UTF_8)));
            return;
        }

        CommandOutput output = command.run(Arrays.copyOfRange(parts, 1, parts.length));

        if (output.success) {
            this.send(output.packet);
        } else {
            IO.println("Error: " + output);
        }
    }
}
