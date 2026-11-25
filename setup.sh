#!/usr/bin/env bash
#
# Set up the CNS environment:
#   1. create (or reuse) the venv at sessions/venv
#   2. install the pinned requirements
#   3. install the toolkit as an editable package, so that from anywhere inside
#      the environment you can  `import cnscrypto as C`  and run the cns-* tools.
#
# Re-runnable and safe to run again after you add new tools to toolkit/.
# Usage:   ./setup.sh          (optionally:  PYTHON=python3.12 ./setup.sh)
#
set -euo pipefail

SESSIONS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SESSIONS_DIR/venv"
TOOLKIT="$SESSIONS_DIR/toolkit"
PY="${PYTHON:-python3}"

echo "[*] CNS environment setup  (sessions dir: $SESSIONS_DIR)"

# 1. venv ---------------------------------------------------------------------
if [ ! -x "$VENV/bin/python" ]; then
    echo "[*] creating virtualenv at $VENV"
    "$PY" -m venv "$VENV"
else
    echo "[*] reusing existing virtualenv at $VENV"
fi
VPY="$VENV/bin/python"

# 2. dependencies -------------------------------------------------------------
echo "[*] upgrading pip / setuptools / wheel"
"$VPY" -m pip install --quiet --upgrade pip setuptools wheel
echo "[*] installing requirements.txt"
"$VPY" -m pip install --quiet -r "$SESSIONS_DIR/requirements.txt"

# 3. toolkit as an importable module + global commands ------------------------
echo "[*] installing the toolkit (editable)"
"$VPY" -m pip install --quiet -e "$TOOLKIT"

# 4. verify -------------------------------------------------------------------
echo "[*] verifying"
"$VPY" - <<'PYEOF'
import cnscrypto as C
assert C.inverse(7, 120) == 103
assert C.wiener and C.hastad_broadcast and C.dsa_x_from_nonce_reuse
print("    import cnscrypto  -> OK  (gmpy2=%s)" % C._HAVE_GMPY2)
PYEOF

cat <<EOF

[+] Done. Activate the environment with:

      source "$VENV/bin/activate"

[+] Then, from any directory, these work:

      python -c "import cnscrypto as C; print(C.find_flag(b'cns{hi}'))"
      cns-rsa      <challenge.json>              # or:  public_keys.txt ciphertexts.txt
      cns-elgamal  <challenge.json>
      cns-dsa      <challenge.json>
      cns-factor   <N> -e 65537
      cns-dlog     -g 2 -t 22 -p 29

[+] Not activating? Prefix with the venv python, e.g.:
      "$VPY" -c "import cnscrypto"

[+] In a hacking-session lab machine without this setup, the toolkit still works
    standalone: copy toolkit/cnscrypto.py next to your script and import it.
EOF
