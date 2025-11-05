<div class="wrap">
    <header>
      <img src="assets/yps_logo.png" alt="YPS">
      <h1>🔐 Password Manager v3.1 — YPS Services LLC</h1>
      <p class="tag">Evidence Before Trust.</p>
      <div>
        <span class="badge">version 3.1</span>
        <span class="badge">license: Commercial</span>
        <span class="badge">python: 3.10+</span>
        <span class="badge">platform: Linux | Windows</span>
      </div>
    </header>

    <section>
      <h2>Key features</h2>
      <ul>
        <li>Encrypted offline vault (<code>vault.dat</code>) with device-bound PBKDF2 + Fernet (AES-256).</li>
        <li>Automatic backup before every save (<code>vault.dat.bak</code>) and <strong><code>restore</code></strong> command.</li>
        <li><strong><code>recent</code></strong> lists last viewed entries by timestamp.</li>
        <li>TOTP support: import Google Authenticator migrations and map secrets.</li>
        <li>Clipboard helpers; Wayland autotype via <code>ydotool</code>.</li>
        <li>License verification banner with unique instance hash.</li>
      </ul>
    </section>

    <section>
      <h2>Quick start</h2>
      <pre><code>python3 passmgr.py</code></pre>
      <p>On first run the app creates:</p>
      <pre><code>vault.dat        # encrypted data store
vault.dat.bak    # rolling backup
vault.salt       # KDF salt
device.key       # device secret
config.json      # defaults (length/charset/modes)</code></pre>
      <p><strong>Linux Wayland:</strong> <code>wl-copy</code> / <code>wl-paste</code> recommended.<br>
         <strong>Windows:</strong> Python 3.10+; script includes clipboard fallback.</p>
    </section>

    <section>
      <h2>Commands</h2>
      <pre><code>add, get, type, gen, update, show, list, search,
delete, recent, restore, verify, about, help, config, quit</code></pre>
      <table>
        <tbody><tr><th>Command</th><th>Purpose</th><th>Examples</th></tr>
        <tr><td><code>add</code></td><td>Create a new entry</td><td><code>add</code></td></tr>
        <tr><td><code>get</code></td><td>Copy user/pw/2FA, updates <code>last_viewed</code></td><td><code>get linkedin.com user</code> · <code>get 4 pw</code> · <code>get site 2fa</code></td></tr>
        <tr><td><code>type</code></td><td>Autotype via ydotool</td><td><code>type 3 up</code></td></tr>
        <tr><td><code>gen</code></td><td>Generate password</td><td><code>gen</code></td></tr>
        <tr><td><code>update</code></td><td>Edit username/password/2FA</td><td><code>update</code></td></tr>
        <tr><td><code>show</code></td><td>Print one entry</td><td><code>show</code></td></tr>
        <tr><td><code>list</code></td><td>Index entries + timestamps</td><td><code>list</code></td></tr>
        <tr><td><code>search</code></td><td>Find by site/user substring</td><td><code>search linkedin</code></td></tr>
        <tr><td><code>recent</code></td><td>Top 5 by <code>last_viewed</code></td><td><code>recent</code></td></tr>
        <tr><td><code>restore</code></td><td>Recover from <code>vault.dat.bak</code></td><td><code>restore</code></td></tr>
        <tr><td><code>verify</code></td><td>Show license status + instance ID</td><td><code>verify</code></td></tr>
        <tr><td><code>config</code></td><td>View or reset defaults</td><td><code>config</code> · <code>config reset</code></td></tr>
      </tbody></table>
      <h3>Examples</h3>
      <pre><code>get 2fa
recent
config reset</code></pre>
    </section>

    <section>
      <h2>Config reference</h2>
      <pre><code>{
  // Default password length for generator
  "default_length": 16,

  // Charsets: U=Upper, L=Lower, D=Digits, S=Symbols
  // e.g., "ULDS" uses all categories
  "default_charset": "ULDS",

  // Default mode for `get`: user | pw | up | 2fa | both
  "default_get_mode": "both",

  // Default mode for `type`: user | pw | up | hotkey
  "default_type_mode": "hotkey"
}</code></pre>
      <p>Reset to defaults:</p>
      <pre><code>config reset</code></pre>
    </section>

    <section>
      <h2>Backup and restore</h2>
      <p>Backups are automatic. To roll back:</p>
      <pre><code>restore</code></pre>
      <p>This validates and replaces <code>vault.dat</code> with the last good <code>.bak</code>.</p>
    </section>

    <section>
      <h2>2FA import</h2>
      <p>Supports Google Authenticator <code>otpauth-migration://…</code> URIs.</p>
      <pre><code>import-2fa
# paste the migration URL</code></pre>
      <p>Map a secret between entries:</p>
      <pre><code>map-2fa 2 7</code></pre>
    </section>

    <section>
      <h2>License and verification</h2>
      <p>Verified builds print:</p>
      <pre><code>[✔] Instance verified: &lt;INSTANCE_ID&gt;  (license OK)</code></pre>
      <p>Public key verification is handled in‑app.<br>
         Contact: <strong>support@ypsservicesllc.com</strong><br>
         Site: <strong>https://ypsservicesllc.com</strong> (redirects from <strong>yps.services</strong>)</p>
    </section>

    <div class="hr"></div>
    <p class="foot">© 2025 YPS Services LLC — Evidence Before Trust.</p>
  </div>
