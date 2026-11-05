import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class MessageManager {
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

    public void sendTextMessage(String message) throws GeneralSecurityException {
        this.send(new Packet(PacketType.MESSAGE, message.getBytes(StandardCharsets.UTF_8)));
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
                    default ->  IO.println("Unknown receiving packet type: " + packet.type());
                }
            }
        } catch (Exception e) {
            IO.println("Error:" + e);
        }

    }
}
