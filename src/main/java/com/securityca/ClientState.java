package com.securityca;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class ClientState {
    public static SecretKey decryptionKey;
    public static boolean isServer;

    public static void setIsServer(boolean isServerIn) {
        isServer = isServerIn;
    }

    public static void setDecryptionKey(SecretKey key) {
        decryptionKey = key;
   }

    public static SecretKey getDecryptionKey() {
        return decryptionKey;
    }
}
