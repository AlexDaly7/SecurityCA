import com.securityca.ClientState;
import com.securityca.crypto.CryptoUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptDecryptTest {

    SecretKey key;
    byte[] salt;

    @BeforeEach
    void EncryptDecryptSetting() {
        char[] password = "testPassword".toCharArray();

        salt = new byte[16];

        new SecureRandom().nextBytes(salt);

        key = CryptoUtils.keyFromPassword(password, salt);

        ClientState.setDecryptionKey(CryptoUtils.keyFromPassword(password, salt));
    }


    @Test
    void EncryptDecrypt() throws GeneralSecurityException {
        byte[] testInput = "example".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(testInput, CryptoUtils.decrypt(key, CryptoUtils.encrypt(key, testInput)));
    }



}
