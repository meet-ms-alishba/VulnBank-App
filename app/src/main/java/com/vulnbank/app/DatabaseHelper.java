package com.vulnbank.app;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * VULN (OWASP M9 - Insecure Data Storage, M4 - Insufficient Input Validation):
 *
 * 1. Passwords are stored in PLAINTEXT in a local SQLite DB that sits at
 *    /data/data/com.vulnbank.app/databases/vulnbank.db -- trivially readable
 *    on a rooted device, or via `adb backup` thanks to allowBackup=true.
 * 2. login() builds its SQL query via string concatenation, so it is
 *    vulnerable to classic SQL injection, e.g. username = `' OR '1'='1`
 *    logs in as the first row in the table without knowing any password.
 */
public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DB_NAME = "vulnbank.db";
    private static final int DB_VERSION = 1;

    public DatabaseHelper(Context ctx) {
        super(ctx, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY," +
                "username TEXT," +
                "password TEXT," +     // VULN: plaintext, should be salted hash (e.g. bcrypt/Argon2)
                "balance REAL," +
                "pin_encrypted TEXT)");

        // Seed data so the app is usable out of the box.
        db.execSQL("INSERT INTO users (username, password, balance, pin_encrypted) VALUES " +
                "('alice', 'alice123', 5230.50, '" + CryptoUtils.encryptPin("1234") + "')");
        db.execSQL("INSERT INTO users (username, password, balance, pin_encrypted) VALUES " +
                "('bob', 'password1', 980.00, '" + CryptoUtils.encryptPin("4321") + "')");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldV, int newV) {
        db.execSQL("DROP TABLE IF EXISTS users");
        onCreate(db);
    }

    /**
     * VULN (CWE-89 SQL Injection): raw string concatenation into rawQuery().
     * Try username = `' OR '1'='1' --` with any password.
     */
    public Cursor login(String username, String password) {
        SQLiteDatabase db = getReadableDatabase();
        String query = "SELECT * FROM users WHERE username = '" + username +
                "' AND password = '" + password + "'";
        return db.rawQuery(query, null); // no parameterized query / bind args
    }

    /** Safe reference version -- parameterized query, no injection possible. */
    public Cursor loginSafe(String username, String password) {
        SQLiteDatabase db = getReadableDatabase();
        return db.rawQuery(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                new String[]{username, password});
    }

    public Cursor getAllUsers() {
        return getReadableDatabase().rawQuery("SELECT * FROM users", null);
    }
}
