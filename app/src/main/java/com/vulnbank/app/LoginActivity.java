package com.vulnbank.app;

import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class LoginActivity extends AppCompatActivity {

    private static final String TAG = "VulnBank/Login";

    private DatabaseHelper dbHelper;
    private EditText userField, passField;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        dbHelper = new DatabaseHelper(this);
        userField = findViewById(R.id.username);
        passField = findViewById(R.id.password);
        Button loginBtn = findViewById(R.id.loginButton);

        loginBtn.setOnClickListener(v -> attemptLogin());
    }

    private void attemptLogin() {
        String user = userField.getText().toString();
        String pass = passField.getText().toString();

        // VULN (OWASP M1, CWE-312/CWE-532 - Sensitive Data in Logs):
        // credentials are written straight to logcat; any app with
        // READ_LOGS on older Android, or `adb logcat`, can read them.
        Log.d(TAG, "Login attempt user=" + user + " pass=" + pass);

        // VULN (OWASP M1 - Improper Credential Usage): hardcoded backdoor
        // bypasses the database check entirely.
        if (user.equals(Constants.ADMIN_BACKDOOR_USER) && pass.equals(Constants.ADMIN_BACKDOOR_PASS)) {
            goToBalance(user);
            return;
        }

        // VULN (CWE-89 SQL Injection): see DatabaseHelper.login().
        // Try: username = ' OR '1'='1  ,  password = anything
        Cursor c = dbHelper.login(user, pass);
        if (c.moveToFirst()) {
            String loggedInUser = c.getString(c.getColumnIndexOrThrow("username"));
            new SessionManager(this).saveSession(loggedInUser, pass);
            goToBalance(loggedInUser);
        } else {
            Toast.makeText(this, "Invalid credentials", Toast.LENGTH_SHORT).show();
        }
        c.close();
    }

    private void goToBalance(String username) {
        Intent i = new Intent(this, BalanceActivity.class);
        i.putExtra("username", username);
        startActivity(i);
        finish();
    }
}
