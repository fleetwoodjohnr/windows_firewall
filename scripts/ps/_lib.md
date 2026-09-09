# Conventions for every script in this directory

These files are the only things `broker/psinvoke.py` will execute, and they are
always run as `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
-File <script> -Param value`.

Rules, all of which the Python side also enforces -- deliberately twice, in two
languages, in two processes:

1. **Every parameter carries `[ValidateSet]`.** The Python allowlist checks the
   value on the way out; the script checks it again on the way in. Neither side
   trusts the other.
2. **Emit JSON on stdout and nothing else.** `ConvertTo-Json -Compress`, always
   with an explicit `-Depth`, because the default of 2 silently truncates nested
   objects into the string "System.Object[]".
3. **Fail loudly.** `$ErrorActionPreference = 'Stop'` at the top, and write the
   reason to stderr with a non-zero exit. A script that half-works and exits 0
   makes the app report protection that is not there.
4. **Reads never change anything**, so the GUI can run them unelevated and
   opening a page never triggers a UAC prompt.
5. **Never interpolate a parameter into a command string.** Pass it as a bound
   parameter. Nothing here should ever need `Invoke-Expression`, and nothing
   here uses it.
