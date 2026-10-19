package com.vulnbank.app;

/**
 * VULN (CWE-798 Hardcoded Credentials, CWE-321 Hardcoded Cryptographic Key):
 * OWASP M1 - Improper Credential Usage, M10 - Insufficient Cryptography.
 *
 * All of these constants end up readable in plaintext in classes.dex after
 * decompiling the APK with jadx -- no reverse engineering effort required,
 * just `strings classes.dex | grep -i key`.
 */
public class Constants {

    // "Master" backdoor login, bypasses normal auth checks in LoginActivity.
    public static final String ADMIN_BACKDOOR_USER = "admin";
    public static final String ADMIN_BACKDOOR_PASS = "SuperSecret123!";

    // Static DES key used by CryptoUtils to "encrypt" PINs before storing them.
    public static final String DES_KEY = "8bytekey";

    // Fake third-party API key, same pattern as real leaked-key incidents.
    public static final String BANKING_API_KEY = "sk_live_51Hx9JvABCDEF1234567890";

    // Base URL is plain HTTP -> ties into the cleartext traffic vuln.
    public static final String API_BASE_URL = "http://api.vulnbank.local/v1/";
}
