package com.vulnbank.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

/**
 * VULN (OWASP M1 - Improper Credential Usage / Insecure Authorization,
 * CWE-926 Improper Export of Android Application Components):
 *
 * This provider is android:exported="true" in the manifest with no
 * android:readPermission / writePermission, so ANY other app on the device
 * (no root needed) can query the full users table, including the plaintext
 * password column and the encrypted PIN, e.g.:
 *
 *   adb shell content query --uri content://com.vulnbank.app.provider/users
 */
public class AccountProvider extends ContentProvider {

    private DatabaseHelper dbHelper;

    @Override
    public boolean onCreate() {
        dbHelper = new DatabaseHelper(getContext());
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                         String[] selectionArgs, String sortOrder) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        // VULN: no caller permission check, no row-level filtering by
        // "current logged in user" -- any caller sees every account.
        return db.query("users", projection, selection, selectionArgs, null, null, sortOrder);
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
    @Override
    public String getType(Uri uri) { return "vnd.android.cursor.dir/users"; }
}
