package com.securityca;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class ClientState {
    public static SecretKey decryptionKey;
    public static boolean isServer;

    public static void setIsServer(boolean isServerIn) {
        isServer = isServerIn;
    }

    public static void setDecryptionKey(String decryptionKey) {
       try {
           ClientState.decryptionKey = KDF.getInstance("HKDF-SHA256").deriveKey("AES", HKDFParameterSpec.ofExtract().addIKM(decryptionKey.getBytes(StandardCharsets.UTF_8)).thenExpand("storage v1".getBytes(StandardCharsets.UTF_8), 32));
       } catch(NoSuchAlgorithmException e){
           IO.println("Error, cryptographic algorithm not available:" + e);
       } catch(NullPointerException e){
           IO.println("Error, null instead of valid object:" + e);
       } catch(InvalidAlgorithmParameterException e) {
           IO.println("Error, invalid/inappropriate algorithm parameters:" + e);
       }  catch(IllegalArgumentException e) {
           IO.println("Error, given illegal/inapropriate argument:" + e);
       }
   }

    public static SecretKey getDecryptionKey() {
        return decryptionKey;
    }
}
