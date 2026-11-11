package com.securityca;

import javax.crypto.SecretKey;

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
