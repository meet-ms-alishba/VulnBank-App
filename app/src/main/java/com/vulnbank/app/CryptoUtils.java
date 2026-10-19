package com.vulnbank.app;

import android.util.Base64;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * VULN (OWASP M10 - Insufficient Cryptography):
 *
 * 1. Uses DES (56-bit, broken since the 1990s) instead of AES-256.
 * 2. Uses ECB mode, which leaks patterns in the plaintext (identical blocks
 *    encrypt to identical ciphertext) and has no IV at all.
 * 3. The key comes from Constants.DES_KEY -- hardcoded in the APK (CWE-321).
 * 4. generateTransactionId() uses java.util.Random seeded by time, which is
 *    predictable -- NOT java.security.SecureRandom (CWE-330).
 */
public class CryptoUtils {

    public static String encryptPin(String pin) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(Constants.DES_KEY.getBytes(), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // VULN: ECB mode
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] enc = cipher.doFinal(pin.getBytes());
            return Base64.encodeToString(enc, Base64.NO_WRAP);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptPin(String encodedPin) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(Constants.DES_KEY.getBytes(), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] dec = cipher.doFinal(Base64.decode(encodedPin, Base64.NO_WRAP));
            return new String(dec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // VULN: predictable "randomness" for transaction/session IDs (CWE-330).
    private static final Random weakRandom = new Random(System.currentTimeMillis());

    public static String generateTransactionId() {
        return "TXN" + Math.abs(weakRandom.nextInt(999999));
    }

    // --- Fixed reference implementation kept here for comparison ---
    // Real apps should do this instead: AES-256-GCM with a per-call random IV,
    // key stored in the Android Keystore (not in source), e.g.:
    //
    //   SecureRandom sr = new SecureRandom();
    //   byte[] iv = new byte[12];
    //   sr.nextBytes(iv);
    //   Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    //   // key retrieved from AndroidKeyStore, never hardcoded
}
