package com.securityca;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class ClientState {
    public static SecretKey decryptionKey;
    public static boolean isServer;

    public static void setIsServer(boolean isServerIn) {
        isServer = isServerIn;
    }

    public static void setDecryptionKey(String decryptionKey) throws GeneralSecurityException {
        ClientState.decryptionKey = KDF.getInstance("HKDF-SHA256").deriveKey("AES", HKDFParameterSpec.ofExtract().addIKM(decryptionKey.getBytes(StandardCharsets.UTF_8)).thenExpand("storage v1".getBytes(StandardCharsets.UTF_8), 32));
    }

    public static SecretKey getDecryptionKey() {
        return decryptionKey;
    }
}
