# SecScan report

Scanned **4** files in 0.01s - **36** finding(s).

| Critical | High | Medium | Low | Info |
|:-:|:-:|:-:|:-:|:-:|
| 2 | 20 | 11 | 3 | 0 |

| Severity | Rule | Location | Issue | CWE |
|---|---|---|---|---|
| CRITICAL | `SEC001` | `app.py:14` | AWS access key ID | CWE-798 |
| CRITICAL | `INJ106` | `upload.php:7` | File inclusion from request data (PHP) | CWE-98 |
| HIGH | `SEC006` | `Login.java:7` | Hard-coded credential | CWE-798 |
| HIGH | `INJ101` | `Login.java:11` | SQL built with string concatenation | CWE-89 |
| HIGH | `DES301` | `Login.java:14` | Unsafe deserialization | CWE-502 |
| HIGH | `SEC006` | `app.py:15` | Hard-coded credential | CWE-798 |
| HIGH | `PY106` | `app.py:23` | SQL query built from dynamic string | CWE-89 |
| HIGH | `PY102` | `app.py:30` | Shell command execution | CWE-78 |
| HIGH | `PY108` | `app.py:35` | Template injection / autoescape off | CWE-1336 |
| HIGH | `PY101` | `app.py:40` | eval()/exec() call | CWE-95 |
| HIGH | `PY103` | `app.py:45` | Unsafe deserialization (pickle/marshal/shelve) | CWE-502 |
| HIGH | `PY104` | `app.py:46` | yaml.load without a safe loader | CWE-502 |
| HIGH | `CRY203` | `app.py:56` | TLS certificate verification disabled | CWE-295 |
| HIGH | `INJ101` | `server.js:11` | SQL built with string concatenation | CWE-89 |
| HIGH | `INJ102` | `server.js:15` | OS command built from dynamic input | CWE-78 |
| HIGH | `INJ107` | `server.js:19` | Path traversal via request input | CWE-22 |
| HIGH | `CRY203` | `server.js:28` | TLS certificate verification disabled | CWE-295 |
| HIGH | `INJ105` | `server.js:29` | Dynamic code evaluation | CWE-95 |
| HIGH | `INJ101` | `upload.php:5` | SQL built with string concatenation | CWE-89 |
| HIGH | `XSS102` | `upload.php:6` | Request data echoed without escaping (PHP) | CWE-79 |
| HIGH | `INJ103` | `upload.php:8` | Shell execution with variable (PHP) | CWE-78 |
| HIGH | `DES301` | `upload.php:9` | Unsafe deserialization | CWE-502 |
| MEDIUM | `CRY201` | `Login.java:12` | Weak hash algorithm (MD5/SHA-1) | CWE-327 |
| MEDIUM | `INJ104` | `Login.java:13` | Runtime.exec / sh -c execution | CWE-78 |
| MEDIUM | `SEC007` | `app.py:16` | High-entropy string (possible secret) | CWE-798 |
| MEDIUM | `PY105` | `app.py:51` | Weak hash (hashlib md5/sha1) | CWE-327 |
| MEDIUM | `PY107` | `app.py:62` | Insecure temporary file (mktemp) | CWE-377 |
| MEDIUM | `CFG401` | `app.py:66` | Debug mode enabled | CWE-489 |
| MEDIUM | `CFG402` | `server.js:8` | Wildcard CORS / allowed hosts | CWE-942 |
| MEDIUM | `XSS101` | `server.js:23` | Unsafe HTML sink | CWE-79 |
| MEDIUM | `CRY204` | `server.js:26` | Insecure randomness for a security value | CWE-338 |
| MEDIUM | `CRY201` | `server.js:27` | Weak hash algorithm (MD5/SHA-1) | CWE-327 |
| MEDIUM | `CRY201` | `upload.php:10` | Weak hash algorithm (MD5/SHA-1) | CWE-327 |
| LOW | `PY109` | `app.py:57` | Exception silently swallowed | CWE-703 |
| LOW | `CFG405` | `app.py:66` | Binds to all network interfaces | CWE-668 |
| LOW | `CFG405` | `server.js:31` | Binds to all network interfaces | CWE-668 |

## Details

### `SEC001` AWS access key ID - CRITICAL
`app.py:14` - CWE-798

```
AWS_ACCESS_KEY_ID = "AKIA****************"
```
**Why it matters:** An AWS access key ID is committed to source code.  
**Fix:** Revoke the key, rotate it, and load credentials from the environment or a secrets manager.

### `INJ106` File inclusion from request data (PHP) - CRITICAL
`upload.php:7` - CWE-98

```
include($_GET['page']);
```
**Why it matters:** include/require uses a request parameter, allowing remote/local file inclusion.  
**Fix:** Never include user-controlled paths; use an allow-list.

### `SEC006` Hard-coded credential - HIGH
`Login.java:7` - CWE-798

```
static final String API_TOKEN = "live*****************";
```
**Why it matters:** A password, secret, token or API key is assigned a literal value.  
**Fix:** Read secrets from environment variables or a secrets manager; never commit them.

### `INJ101` SQL built with string concatenation - HIGH
`Login.java:11` - CWE-89

```
ResultSet r = s.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
```
**Why it matters:** A SQL statement is assembled from dynamic values, enabling SQL injection.  
**Fix:** Use parameterised queries / prepared statements.

### `DES301` Unsafe deserialization - HIGH
`Login.java:14` - CWE-502

```
ObjectInputStream in = new ObjectInputStream(new FileInputStream("session.bin"));
```
**Why it matters:** Deserializing untrusted data can lead to remote code execution.  
**Fix:** Use a data-only format such as JSON and validate the schema.

### `SEC006` Hard-coded credential - HIGH
`app.py:15` - CWE-798

```
DB_PASSWORD = "Supe**********"
```
**Why it matters:** A password, secret, token or API key is assigned a literal value.  
**Fix:** Read secrets from environment variables or a secrets manager; never commit them.

### `PY106` SQL query built from dynamic string - HIGH
`app.py:23` - CWE-89

```
row = db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchone()
```
**Why it matters:** A query passed to execute() is built with f-strings, %, + or .format().  
**Fix:** Pass parameters separately: cursor.execute(sql, params).

### `PY102` Shell command execution - HIGH
`app.py:30` - CWE-78

```
return subprocess.check_output("ping -c 1 " + host, shell=True)
```
**Why it matters:** os.system, os.popen or subprocess(shell=True) invoke a shell.  
**Fix:** Call subprocess with an argument list and shell=False.

### `PY108` Template injection / autoescape off - HIGH
`app.py:35` - CWE-1336

```
return render_template_string("<h1>Hello " + request.args.get("n", "") + "</h1>")
```
**Why it matters:** Rendering dynamically built templates or disabling autoescape enables SSTI/XSS.  
**Fix:** Render static templates and keep autoescape enabled.

### `PY101` eval()/exec() call - HIGH
`app.py:40` - CWE-95

```
return str(eval(request.args.get("expr")))
```
**Why it matters:** eval/exec run arbitrary code.  
**Fix:** Use ast.literal_eval or a purpose-built parser.

### `PY103` Unsafe deserialization (pickle/marshal/shelve) - HIGH
`app.py:45` - CWE-502

```
obj = pickle.loads(request.data)
```
**Why it matters:** Loading untrusted pickle data executes arbitrary code.  
**Fix:** Use JSON or another data-only format.

### `PY104` yaml.load without a safe loader - HIGH
`app.py:46` - CWE-502

```
cfg = yaml.load(request.data)
```
**Why it matters:** yaml.load can instantiate arbitrary objects.  
**Fix:** Use yaml.safe_load.

### `CRY203` TLS certificate verification disabled - HIGH
`app.py:56` - CWE-295

```
return requests.get(url, verify=False).text
```
**Why it matters:** Disabling certificate checks exposes traffic to man-in-the-middle attacks.  
**Fix:** Keep verification on; add the CA bundle you need instead of disabling checks.

### `INJ101` SQL built with string concatenation - HIGH
`server.js:11` - CWE-89

```
db.query("SELECT * FROM items WHERE name = '" + req.query.q + "'", (err, rows) => res.json(rows));
```
**Why it matters:** A SQL statement is assembled from dynamic values, enabling SQL injection.  
**Fix:** Use parameterised queries / prepared statements.

### `INJ102` OS command built from dynamic input - HIGH
`server.js:15` - CWE-78

```
exec("ls " + req.query.dir, (e, out) => res.send(out));
```
**Why it matters:** A shell command is built from variables, enabling command injection.  
**Fix:** Avoid the shell; pass an argument list to an exec API and validate input.

### `INJ107` Path traversal via request input - HIGH
`server.js:19` - CWE-22

```
res.send(fs.readFileSync(req.query.path));
```
**Why it matters:** A file API receives request data directly.  
**Fix:** Resolve the path and confirm it stays inside an allowed base directory.

### `CRY203` TLS certificate verification disabled - HIGH
`server.js:28` - CWE-295

```
const agent = { rejectUnauthorized: false };
```
**Why it matters:** Disabling certificate checks exposes traffic to man-in-the-middle attacks.  
**Fix:** Keep verification on; add the CA bundle you need instead of disabling checks.

### `INJ105` Dynamic code evaluation - HIGH
`server.js:29` - CWE-95

```
app.get("/eval", (req, res) => res.send(String(eval(req.query.code))));
```
**Why it matters:** eval()/new Function() executes dynamically built code.  
**Fix:** Remove eval; use JSON.parse or a safe expression parser.

### `INJ101` SQL built with string concatenation - HIGH
`upload.php:5` - CWE-89

```
$result = mysqli_query($conn, "SELECT * FROM orders WHERE id = " . $id);
```
**Why it matters:** A SQL statement is assembled from dynamic values, enabling SQL injection.  
**Fix:** Use parameterised queries / prepared statements.

### `XSS102` Request data echoed without escaping (PHP) - HIGH
`upload.php:6` - CWE-79

```
echo "Hello " . $_GET['name'];
```
**Why it matters:** User input from a superglobal is echoed directly.  
**Fix:** Wrap output with htmlspecialchars($x, ENT_QUOTES, 'UTF-8').

### `INJ103` Shell execution with variable (PHP) - HIGH
`upload.php:8` - CWE-78

```
system("convert " . $_POST['file'] . " out.png");
```
**Why it matters:** A PHP shell-execution function receives a variable.  
**Fix:** Use escapeshellarg() and avoid shell functions where possible.

### `DES301` Unsafe deserialization - HIGH
`upload.php:9` - CWE-502

```
$data = unserialize($_COOKIE['prefs']);
```
**Why it matters:** Deserializing untrusted data can lead to remote code execution.  
**Fix:** Use a data-only format such as JSON and validate the schema.

### `CRY201` Weak hash algorithm (MD5/SHA-1) - MEDIUM
`Login.java:12` - CWE-327

```
MessageDigest md = MessageDigest.getInstance("MD5");
```
**Why it matters:** MD5 and SHA-1 are broken for security purposes.  
**Fix:** Use SHA-256+ for integrity, and bcrypt/scrypt/Argon2 for passwords.

### `INJ104` Runtime.exec / sh -c execution - MEDIUM
`Login.java:13` - CWE-78

```
Runtime.getRuntime().exec("echo " + user);
```
**Why it matters:** Process execution via Runtime.exec or a shell wrapper.  
**Fix:** Use ProcessBuilder with an argument list; never concatenate user input.

### `SEC007` High-entropy string (possible secret) - MEDIUM
`app.py:16` - CWE-798

```
SESSION_SIGNING_KEY = "q8Vd************************************"
```
**Why it matters:** A long random-looking string literal may be an embedded key or token.  
**Fix:** If this is a credential, rotate it and load it from the environment.

### `PY105` Weak hash (hashlib md5/sha1) - MEDIUM
`app.py:51` - CWE-327

```
return hashlib.md5(pw.encode()).hexdigest()
```
**Why it matters:** MD5/SHA-1 are broken for security purposes.  
**Fix:** Use hashlib.sha256 or a password hasher (bcrypt/argon2).

### `PY107` Insecure temporary file (mktemp) - MEDIUM
`app.py:62` - CWE-377

```
return tempfile.mktemp()
```
**Why it matters:** tempfile.mktemp is vulnerable to race conditions.  
**Fix:** Use tempfile.mkstemp or NamedTemporaryFile.

### `CFG401` Debug mode enabled - MEDIUM
`app.py:66` - CWE-489

```
app.run(host="0.0.0.0", debug=True)
```
**Why it matters:** Debug features leak stack traces and may expose an interactive console.  
**Fix:** Disable debug in production and drive it from environment configuration.

### `CFG402` Wildcard CORS / allowed hosts - MEDIUM
`server.js:8` - CWE-942

```
app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });
```
**Why it matters:** Allowing every origin or host weakens browser and host-header protections.  
**Fix:** List the specific origins/hosts that are allowed.

### `XSS101` Unsafe HTML sink - MEDIUM
`server.js:23` - CWE-79

```
res.send('<script>document.getElementById("x").innerHTML = "${req.query.msg}"</script>');
```
**Why it matters:** Assigning untrusted data to innerHTML/document.write enables XSS.  
**Fix:** Use textContent or sanitise with a trusted library such as DOMPurify.

### `CRY204` Insecure randomness for a security value - MEDIUM
`server.js:26` - CWE-338

```
const token = Math.random().toString(36);
```
**Why it matters:** A non-cryptographic PRNG is used for a token, password or key.  
**Fix:** Use secrets (Python), crypto.randomBytes (Node) or SecureRandom (Java).

### `CRY201` Weak hash algorithm (MD5/SHA-1) - MEDIUM
`server.js:27` - CWE-327

```
const digest = crypto.createHash("md5").update("data").digest("hex");
```
**Why it matters:** MD5 and SHA-1 are broken for security purposes.  
**Fix:** Use SHA-256+ for integrity, and bcrypt/scrypt/Argon2 for passwords.

### `CRY201` Weak hash algorithm (MD5/SHA-1) - MEDIUM
`upload.php:10` - CWE-327

```
$hash = md5($_POST['password']);
```
**Why it matters:** MD5 and SHA-1 are broken for security purposes.  
**Fix:** Use SHA-256+ for integrity, and bcrypt/scrypt/Argon2 for passwords.

### `PY109` Exception silently swallowed - LOW
`app.py:57` - CWE-703

```
except Exception:
```
**Why it matters:** `except: pass` hides failures, including security-relevant ones.  
**Fix:** Handle or at least log the exception.

### `CFG405` Binds to all network interfaces - LOW
`app.py:66` - CWE-668

```
app.run(host="0.0.0.0", debug=True)
```
**Why it matters:** Listening on 0.0.0.0 exposes the service on every interface.  
**Fix:** Bind to 127.0.0.1 unless external access is required, and firewall it.

### `CFG405` Binds to all network interfaces - LOW
`server.js:31` - CWE-668

```
app.listen(3000, "0.0.0.0");
```
**Why it matters:** Listening on 0.0.0.0 exposes the service on every interface.  
**Fix:** Bind to 127.0.0.1 unless external access is required, and firewall it.

