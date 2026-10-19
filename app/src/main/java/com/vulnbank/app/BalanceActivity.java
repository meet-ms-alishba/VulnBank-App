package com.vulnbank.app;

import android.database.Cursor;
import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

/**
 * VULN (OWASP M1 - Improper Authorization / "Broken Access Control"):
 *
 * This activity is android:exported="true" (see AndroidManifest.xml) and
 * NEVER checks SessionManager.isLoggedIn() before showing account data.
 * Any other app, or a direct adb command, can jump straight here and skip
 * LoginActivity entirely:
 *
 *   adb shell am start -n com.vulnbank.app/.BalanceActivity --es username alice
 */
public class BalanceActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_balance);

        // VULN: no `if (!new SessionManager(this).isLoggedIn()) { finish(); return; }` guard here.

        String username = getIntent().getStringExtra("username");
        if (username == null) username = "alice"; // falls back to a real account either way

        DatabaseHelper db = new DatabaseHelper(this);
        Cursor c = db.getAllUsers();
        TextView tv = findViewById(R.id.balanceText);
        StringBuilder sb = new StringBuilder();

        while (c.moveToNext()) {
            String u = c.getString(c.getColumnIndexOrThrow("username"));
            if (u.equals(username)) {
                double balance = c.getDouble(c.getColumnIndexOrThrow("balance"));
                String encPin = c.getString(c.getColumnIndexOrThrow("pin_encrypted"));
                sb.append("User: ").append(u).append("\n")
                  .append("Balance: $").append(balance).append("\n")
                  .append("PIN (decrypted): ").append(CryptoUtils.decryptPin(encPin));
            }
        }
        c.close();
        tv.setText(sb.toString());
    }
}
