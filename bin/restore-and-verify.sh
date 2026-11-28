#!/usr/bin/env bash
set -euo pipefail

# Restore a sealed migration bundle onto a target workstation and verify epistemic integrity fail-closed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC=""
GEMINI_DIR="${HOME}/.gemini"
EXPEDITION_DIR="${HOME}/Projects/expedition"
CID=""
INCLUDE_AUTH=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: restore-and-verify.sh --src <bundle-dir> [options]

Options:
  --src <dir>              Source bundle directory containing payload/ and MIGRATION_SHA256SUMS
  --gemini-dir <dir>       Target Gemini home directory (default: $HOME/.gemini)
  --expedition-dir <dir>   Target expedition directory (default: $HOME/Projects/expedition)
  --cid <cid>              Coordinator conversation ID (auto-read from MIGRATION_RECEIPT.json if omitted)
  --include-auth           Overwrite target oauth_creds.json / installation_id from bundle
  --dry-run                Verify bundle fail-closed and preview planned restore without modifying disk
  --help                   Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src)
      SRC="${2:?--src requires a value}"
      shift 2
      ;;
    --gemini-dir)
      GEMINI_DIR="${2:?--gemini-dir requires a value}"
      shift 2
      ;;
    --expedition-dir)
      EXPEDITION_DIR="${2:?--expedition-dir requires a value}"
      shift 2
      ;;
    --cid)
      CID="${2:?--cid requires a value}"
      shift 2
      ;;
    --include-auth)
      INCLUDE_AUTH=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf '[restore-and-verify] ERROR: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${SRC}" ]]; then
  printf '[restore-and-verify] ERROR: --src is required\n' >&2
  usage >&2
  exit 2
fi

MANIFEST="${SRC}/MIGRATION_SHA256SUMS"
RECEIPT="${SRC}/MIGRATION_RECEIPT.json"
PAYLOAD="${SRC}/payload"
TARGET_AG="${GEMINI_DIR}/antigravity-cli"
TARGET_CFG="${GEMINI_DIR}/config"
PRESENCE_DIR="${TARGET_AG}/presence"

# Fail-closed path, symlink, payload inventory, receipt seal, and CID preflight BEFORE any mkdir/rsync.
# Emits 9 canonical absolute paths + validated CID (one per line; newlines/colons/leading '-' refused).
PREFLIGHT_RAW="$(python3 -I -B - "${SRC}" "${MANIFEST}" "${RECEIPT}" "${PAYLOAD}" "${GEMINI_DIR}" "${TARGET_AG}" "${TARGET_CFG}" "${EXPEDITION_DIR}" "${PRESENCE_DIR}" "${CID}" <<'PY'
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys

(
    src_raw,
    manifest_raw,
    receipt_raw,
    payload_raw,
    gemini_raw,
    target_ag_raw,
    target_cfg_raw,
    expedition_raw,
    presence_raw,
    cli_cid,
) = sys.argv[1:11]

FORBIDDEN_SYS_PREFIXES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var",
)
ALLOWED_MANIFEST_PREFIXES = ("gemini-antigravity-cli", "gemini-config", "expedition")
CID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
MAX_RECEIPT_BYTES = 1048576
MAX_MANIFEST_BYTES = 16777216
MAX_JSON_INT_DIGITS = 64
MAX_JSON_DEPTH = 32


def fail(msg: str) -> None:
    sys.stderr.write(f"[restore-and-verify] ERROR: {msg}\n")
    raise SystemExit(2)


def is_forbidden_system_path(path_str: str) -> bool:
    norm = re.sub(r"^/+", "/", path_str)
    if norm == "/":
        return True
    if norm.startswith("/dev/shm/"):
        return False
    return any(norm == pfx or norm.startswith(pfx + "/") for pfx in FORBIDDEN_SYS_PREFIXES)


def check_safe_path(raw: str, label: str) -> Path:
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw or raw.startswith("//"):
        fail(f"{label} contains empty value, control char, or leading '//'")
    if raw.startswith("-"):
        fail(f"{label} must not start with '-': {raw}")
    if ":" in raw:
        fail(f"{label} must not contain ':' (local paths only): {raw}")
    p = Path(raw)
    if ".." in p.parts:
        fail(f"{label} contains parent traversal '..'")
    try:
        raw.encode("utf-8")
        abs_path = Path(os.path.abspath(raw))
        if os.path.islink(abs_path):
            fail(f"refusing symlink for {label}: {raw}")
        real_parent = Path(os.path.realpath(str(abs_path.parent)))
    except (OSError, UnicodeEncodeError) as exc:
        fail(f"{label} path resolution failed: {exc}")
    resolved = real_parent / abs_path.name
    resolved_str = resolved.as_posix()
    if ":" in resolved_str or "\n" in resolved_str or "\r" in resolved_str:
        fail(f"{label} resolved path contains forbidden character: {resolved_str}")
    if is_forbidden_system_path(resolved_str):
        fail(f"{label} targets forbidden system path: {resolved_str}")
    if os.path.islink(resolved):
        fail(f"refusing symlink for {label}: {resolved_str}")
    return resolved


def check_dir_nofol(path: Path, label: str, *, required: bool) -> None:
    if not os.path.lexists(path):
        if required:
            fail(f"missing required directory for {label}: {path}")
        return
    try:
        dfd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"{label} must be a non-symlink directory: {exc}")
    os.close(dfd)


def read_reg_bytes_nofol(path: Path, label: str, max_bytes: int) -> bytes:
    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(f"{label} must be a regular file: {path}")
        if st.st_size > max_bytes:
            fail(f"{label} exceeds {max_bytes} byte cap")
        os.set_blocking(fd, True)
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read(max_bytes)
    except OSError as exc:
        fail(f"{label} read failed: {exc}")
    finally:
        if fd >= 0:
            os.close(fd)


def check_reg_nofol(path: Path, label: str, *, required: bool) -> None:
    if not os.path.lexists(path):
        if required:
            fail(f"missing required regular file for {label}: {path}")
        return
    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(f"{label} must be a regular file: {path}")
    except OSError as exc:
        fail(f"{label} open failed: {exc}")
    finally:
        if fd >= 0:
            os.close(fd)


def check_json_depth(obj: object, label: str) -> None:
    stack: list[tuple[object, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            fail(f"{label} exceeds max JSON nesting depth {MAX_JSON_DEPTH}")
        if type(cur) is dict:
            for v in cur.values():
                stack.append((v, depth + 1))
        elif type(cur) is list:
            for v in cur:
                stack.append((v, depth + 1))


def load_strict_receipt(path: Path) -> dict:
    raw_bytes = read_reg_bytes_nofol(path, "MIGRATION_RECEIPT.json", MAX_RECEIPT_BYTES)
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"MIGRATION_RECEIPT.json invalid UTF-8: {exc}")

    def reject_const(tok: str) -> None:
        fail(f"MIGRATION_RECEIPT.json non-finite constant forbidden: {tok!r}")

    def reject_float(tok: str) -> None:
        fail(f"MIGRATION_RECEIPT.json float literal forbidden: {tok!r}")

    def parse_bounded_int(tok: str) -> int:
        digits = tok[1:] if tok.startswith("-") else tok
        if len(digits) > MAX_JSON_INT_DIGITS:
            fail(f"MIGRATION_RECEIPT.json integer exceeds {MAX_JSON_INT_DIGITS} digits")
        return int(tok)

    def reject_dup_keys(pairs: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for k, v in pairs:
            if k in out:
                fail(f"MIGRATION_RECEIPT.json duplicate key forbidden: {k!r}")
            out[k] = v
        return out

    try:
        obj = json.loads(
            raw_text,
            parse_constant=reject_const,
            parse_float=reject_float,
            parse_int=parse_bounded_int,
            object_pairs_hook=reject_dup_keys,
        )
    except RecursionError as exc:
        fail(f"MIGRATION_RECEIPT.json exceeds max JSON nesting depth: {exc}")
    except ValueError as exc:
        fail(f"MIGRATION_RECEIPT.json invalid JSON: {exc}")
    check_json_depth(obj, "MIGRATION_RECEIPT.json")
    if type(obj) is not dict:
        fail("MIGRATION_RECEIPT.json root must be a JSON object")
    return obj


def inventory_payload_nofol(payload_root: Path) -> dict[str, int]:
    """Walk payload/ using O_NOFOLLOW; refuse any symlink or non-regular file."""
    files: dict[str, int] = {}
    stack: list[tuple[Path, str]] = [(payload_root, "")]
    while stack:
        cur_dir, rel_dir = stack.pop()
        dfd = -1
        try:
            dfd = os.open(str(cur_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            entries = sorted(os.listdir(dfd))
            for name in entries:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if stat.S_ISLNK(st.st_mode):
                    fail(f"refusing symlink inside payload: {rel}")
                if stat.S_ISDIR(st.st_mode):
                    stack.append((cur_dir / name, rel))
                elif stat.S_ISREG(st.st_mode):
                    files[rel] = st.st_size
                else:
                    fail(f"refusing non-regular entry inside payload: {rel}")
        except OSError as exc:
            fail(f"payload walk failed at {rel_dir or '.'}: {exc}")
        finally:
            if dfd >= 0:
                os.close(dfd)
    return files


src_p = check_safe_path(src_raw, "--src")
manifest_p = check_safe_path(manifest_raw, "MIGRATION_SHA256SUMS")
receipt_p = check_safe_path(receipt_raw, "MIGRATION_RECEIPT.json")
payload_p = check_safe_path(payload_raw, "payload")
payload_ag_p = check_safe_path(str(Path(payload_raw) / "gemini-antigravity-cli"), "payload/gemini-antigravity-cli")
payload_cfg_p = check_safe_path(str(Path(payload_raw) / "gemini-config"), "payload/gemini-config")
payload_exp_p = check_safe_path(str(Path(payload_raw) / "expedition"), "payload/expedition")

gemini_p = check_safe_path(gemini_raw, "--gemini-dir")
target_ag_p = check_safe_path(target_ag_raw, "target antigravity-cli")
target_cfg_p = check_safe_path(target_cfg_raw, "target config")
expedition_p = check_safe_path(expedition_raw, "--expedition-dir")
presence_p = check_safe_path(presence_raw, "target presence")
install_id_p = check_safe_path(str(Path(target_ag_raw) / "installation_id"), "target installation_id")
oauth_p = check_safe_path(str(Path(gemini_raw) / "oauth_creds.json"), "target oauth_creds.json")

check_dir_nofol(src_p, "--src", required=True)
check_reg_nofol(manifest_p, "MIGRATION_SHA256SUMS", required=True)
check_dir_nofol(payload_p, "payload", required=True)
check_dir_nofol(payload_ag_p, "payload/gemini-antigravity-cli", required=True)
check_dir_nofol(payload_cfg_p, "payload/gemini-config", required=False)
check_dir_nofol(payload_exp_p, "payload/expedition", required=True)

check_dir_nofol(gemini_p, "--gemini-dir", required=False)
check_dir_nofol(target_ag_p, "target antigravity-cli", required=False)
check_dir_nofol(target_cfg_p, "target config", required=False)
check_dir_nofol(expedition_p, "--expedition-dir", required=False)
check_dir_nofol(presence_p, "target presence", required=False)
check_reg_nofol(install_id_p, "target installation_id", required=False)
check_reg_nofol(oauth_p, "target oauth_creds.json", required=False)

# Parse manifest, validate allowed root prefixes, and enforce 1-to-1 parity with payload/ files (no unlisted files).
manifest_bytes = read_reg_bytes_nofol(manifest_p, "MIGRATION_SHA256SUMS", MAX_MANIFEST_BYTES)
try:
    manifest_text = manifest_bytes.decode("utf-8")
except UnicodeDecodeError as exc:
    fail(f"MIGRATION_SHA256SUMS invalid UTF-8: {exc}")
manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

manifest_rels: set[str] = set()
for idx, line in enumerate(manifest_text.splitlines(), start=1):
    if not line.strip():
        continue
    if "  " not in line:
        fail(f"MIGRATION_SHA256SUMS:{idx}: malformed manifest line")
    digest, relpath = line.split("  ", 1)
    if not HEX64_RE.match(digest):
        fail(f"MIGRATION_SHA256SUMS:{idx}: invalid sha256 digest")
    if relpath.startswith("/"):
        fail(f"MIGRATION_SHA256SUMS:{idx}: absolute path forbidden: {relpath!r}")
    parts = Path(relpath).parts
    if len(parts) < 2 or ".." in parts or parts[0] not in ALLOWED_MANIFEST_PREFIXES:
        fail(f"MIGRATION_SHA256SUMS:{idx}: disallowed manifest path/prefix: {relpath!r}")
    if relpath in manifest_rels:
        fail(f"MIGRATION_SHA256SUMS:{idx}: duplicate manifest entry: {relpath!r}")
    manifest_rels.add(relpath)

if not manifest_rels:
    fail("MIGRATION_SHA256SUMS contains zero entries")

payload_files = inventory_payload_nofol(payload_p)
unlisted = sorted(set(payload_files.keys()) - manifest_rels)
if unlisted:
    fail(f"refusing unlisted payload file(s) not sealed in MIGRATION_SHA256SUMS: {unlisted[0]}")
missing_in_payload = sorted(manifest_rels - set(payload_files.keys()))
if missing_in_payload:
    fail(f"manifest entry missing from payload: {missing_in_payload[0]}")

if cli_cid and not CID_RE.match(cli_cid):
    fail(f"invalid --cid format: {cli_cid!r}")

resolved_cid = cli_cid
if os.path.lexists(receipt_p):
    receipt_obj = load_strict_receipt(receipt_p)
    if receipt_obj.get("schema") != "aletheia.migration_receipt.v1":
        fail(f"MIGRATION_RECEIPT.json invalid schema: {receipt_obj.get('schema')!r}")
    receipt_cid = receipt_obj.get("cid")
    if type(receipt_cid) is not str or not CID_RE.match(receipt_cid):
        fail(f"MIGRATION_RECEIPT.json invalid cid: {receipt_cid!r}")
    if cli_cid and cli_cid != receipt_cid:
        fail(f"--cid ({cli_cid}) does not match MIGRATION_RECEIPT.json cid ({receipt_cid})")
    receipt_msha = receipt_obj.get("manifest_sha256")
    if type(receipt_msha) is not str or not HEX64_RE.match(receipt_msha):
        fail("MIGRATION_RECEIPT.json missing or invalid manifest_sha256")
    if not hmac.compare_digest(receipt_msha, manifest_sha256):
        fail("MIGRATION_RECEIPT.json manifest_sha256 does not match MIGRATION_SHA256SUMS")
    receipt_fc = receipt_obj.get("file_count")
    if type(receipt_fc) is not int or receipt_fc != len(payload_files):
        fail(f"MIGRATION_RECEIPT.json file_count mismatch: {receipt_fc!r} != {len(payload_files)}")
    receipt_tb = receipt_obj.get("total_bytes")
    actual_tb = sum(payload_files.values())
    if type(receipt_tb) is not int or receipt_tb != actual_tb:
        fail(f"MIGRATION_RECEIPT.json total_bytes mismatch: {receipt_tb!r} != {actual_tb}")
    resolved_cid = receipt_cid

if not resolved_cid:
    fail("could not determine CID; pass --cid <CID>")

for item in (
    resolved_cid,
    src_p.as_posix(),
    manifest_p.as_posix(),
    payload_p.as_posix(),
    gemini_p.as_posix(),
    target_ag_p.as_posix(),
    target_cfg_p.as_posix(),
    expedition_p.as_posix(),
    presence_p.as_posix(),
):
    print(item)
PY
)"

PREFLIGHT_LINES=()
while IFS= read -r line; do
  PREFLIGHT_LINES+=("${line}")
done <<< "${PREFLIGHT_RAW}"

if [[ "${#PREFLIGHT_LINES[@]}" -ne 9 ]]; then
  printf '[restore-and-verify] ERROR: preflight returned malformed output\n' >&2
  exit 2
fi

CID="${PREFLIGHT_LINES[0]}"
SRC="${PREFLIGHT_LINES[1]}"
MANIFEST="${PREFLIGHT_LINES[2]}"
PAYLOAD="${PREFLIGHT_LINES[3]}"
GEMINI_DIR="${PREFLIGHT_LINES[4]}"
TARGET_AG="${PREFLIGHT_LINES[5]}"
TARGET_CFG="${PREFLIGHT_LINES[6]}"
EXPEDITION_DIR="${PREFLIGHT_LINES[7]}"
PRESENCE_DIR="${PREFLIGHT_LINES[8]}"

# Step 1: Fail-closed PRE-RESTORE verification against source payload BEFORE --dry-run exit or ANY target writes.
PRE_CFG_ARG=()
if [[ -d "${PAYLOAD}/gemini-config" ]]; then
  PRE_CFG_ARG=(--config-dir "${PAYLOAD}/gemini-config")
fi
if ! PRE_OUT="$(
  python3 -I -B "${SCRIPT_DIR}/verify_epistemic_integrity.py" \
    --manifest "${MANIFEST}" \
    --gemini-dir "${PAYLOAD}/gemini-antigravity-cli" \
    ${PRE_CFG_ARG[@]+"${PRE_CFG_ARG[@]}"} \
    --expedition-dir "${PAYLOAD}/expedition" \
    --cid "${CID}" \
    --json 2>&1
)"; then
  printf '[restore-and-verify] ERROR: pre-restore verification failed; aborting before target writes\n' >&2
  printf '%s\n' "${PRE_OUT}" >&2
  exit 2
fi
printf '[restore-and-verify] Pre-restore payload verification PASS\n'

if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '[restore-and-verify] DRY-RUN: src=%s cid=%s include_auth=%d\n' "${SRC}" "${CID}" "${INCLUDE_AUTH}"
  printf '[restore-and-verify] DRY-RUN: pre-restore verification passed against %s\n' "${PAYLOAD}"
  printf '[restore-and-verify] DRY-RUN: would restore (--no-links) to %s, %s, and %s\n' "${TARGET_AG}" "${TARGET_CFG}" "${EXPEDITION_DIR}"
  printf '[restore-and-verify] DRY-RUN: would strip stale locks in %s\n' "${PRESENCE_DIR}"
  printf '[restore-and-verify] DRY-RUN: would run post-restore verify_epistemic_integrity.py fail-closed\n'
  printf '[restore-and-verify] DRY-RUN: launch command -> agy --resume %s\n' "${CID}"
  exit 0
fi

# Step 2: Hydrate verified payload to canonical absolute targets with --no-links --no-devices --no-specials.
mkdir -p -- "${TARGET_AG}" "${TARGET_CFG}" "${EXPEDITION_DIR}"

# Preserve existing target host OAuth / installation identity unless --include-auth is explicitly passed.
PRESERVE_AUTH_FLAGS=()
SKIP_AUTH_ARG=()
if [[ "${INCLUDE_AUTH}" -eq 0 ]]; then
  if [[ -f "${TARGET_AG}/installation_id" && ! -L "${TARGET_AG}/installation_id" ]]; then
    PRESERVE_AUTH_FLAGS+=(--exclude='installation_id')
    SKIP_AUTH_ARG+=(--skip-auth-files)
    printf '[restore-and-verify] Preserving existing target %s/installation_id\n' "${TARGET_AG}"
  fi
  if [[ -f "${GEMINI_DIR}/oauth_creds.json" && ! -L "${GEMINI_DIR}/oauth_creds.json" ]]; then
    PRESERVE_AUTH_FLAGS+=(--exclude='oauth_creds.json')
    printf '[restore-and-verify] Preserving existing target %s/oauth_creds.json\n' "${GEMINI_DIR}"
  fi
fi

rsync -a --no-links --no-devices --no-specials \
  --exclude='presence/*.lock' \
  ${PRESERVE_AUTH_FLAGS[@]+"${PRESERVE_AUTH_FLAGS[@]}"} \
  -- "${PAYLOAD}/gemini-antigravity-cli/" "${TARGET_AG}/"

if [[ -d "${PAYLOAD}/gemini-config" ]]; then
  rsync -a --no-links --no-devices --no-specials -- "${PAYLOAD}/gemini-config/" "${TARGET_CFG}/"
fi

rsync -a --no-links --no-devices --no-specials -- "${PAYLOAD}/expedition/" "${EXPEDITION_DIR}/"

# Step 3: Strip any stale presence lock files cleanly without find -delete or following symlinks.
if [[ -L "${PRESENCE_DIR}" ]]; then
  printf '[restore-and-verify] ERROR: refusing symlinked presence dir %s\n' "${PRESENCE_DIR}" >&2
  exit 2
elif [[ -d "${PRESENCE_DIR}" ]]; then
  python3 -I -B -c '
import os, stat, sys
pdir = sys.argv[1]
dfd = os.open(pdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for entry in os.listdir(dfd):
        if entry.endswith(".lock"):
            st = os.stat(entry, dir_fd=dfd, follow_symlinks=False)
            if stat.S_ISREG(st.st_mode):
                os.unlink(entry, dir_fd=dfd)
finally:
    os.close(dfd)
' "${PRESENCE_DIR}"
fi

# Step 4: Run fail-closed POST-RESTORE epistemic integrity verifier against restored targets.
python3 -I -B "${SCRIPT_DIR}/verify_epistemic_integrity.py" \
  --manifest "${MANIFEST}" \
  --gemini-dir "${TARGET_AG}" \
  --config-dir "${TARGET_CFG}" \
  --expedition-dir "${EXPEDITION_DIR}" \
  --cid "${CID}" \
  ${SKIP_AUTH_ARG[@]+"${SKIP_AUTH_ARG[@]}"} \
  --json

printf '\n[restore-and-verify] RESTORE VERIFIED PASS\n'
printf '[restore-and-verify] Next step: agy --resume %s\n' "${CID}"
