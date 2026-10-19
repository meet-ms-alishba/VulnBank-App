package com.vulnbank.app;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * VULN (OWASP M9 - Insecure Data Storage):
 *
 * Regular (non-encrypted) SharedPreferences store the logged-in username,
 * a "remember me" plaintext password, and an auth flag. The backing XML
 * file at /data/data/com.vulnbank.app/shared_prefs/session.xml is plaintext
 * and readable on a rooted device or restorable via `adb backup`.
 *
 * Fix: use EncryptedSharedPreferences (androidx.security:security-crypto)
 * with a key from the Android Keystore, and never store raw passwords --
 * store a short-lived token instead.
 */
public class SessionManager {

    private final SharedPreferences prefs;

    public SessionManager(Context ctx) {
        prefs = ctx.getSharedPreferences("session", Context.MODE_PRIVATE);
    }

    public void saveSession(String username, String plaintextPassword) {
        SharedPreferences.Editor e = prefs.edit();
        e.putString("username", username);
        e.putString("password", plaintextPassword); // VULN: plaintext password at rest
        e.putBoolean("logged_in", true);
        e.apply();
    }

    public boolean isLoggedIn() {
        return prefs.getBoolean("logged_in", false);
    }

    public String getUsername() {
        return prefs.getString("username", null);
    }

    public void logout() {
        prefs.edit().clear().apply();
    }
}
