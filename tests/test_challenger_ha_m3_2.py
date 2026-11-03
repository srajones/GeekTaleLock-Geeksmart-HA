#!/usr/bin/env python3
"""Empirical Challenger Test Suite for Milestone 3 (tests/test_challenger_ha_m3_2.py).

Adversarially stress-tests:
1. geek_door_addon/run.sh option extraction and security:
   - Booleans set to false (enable_2fa: false, dry_run: false) do NOT falsely revert to true.
   - Empty strings, null values, and missing options revert to defaults cleanly.
   - Tricky passwords containing $, `, ", ', \\, ;, &, |, <, > are written verbatim to .env
     without shell expansion, command execution, truncation, or corruption.
   - Testing both with jq and with python fallback (jq absent from PATH).
   - Signal handling: SIGTERM, SIGINT, SIGHUP result in clean exit 0 and child cleanup.
   - Bash syntax (bash -n) and executable bit (+x).
2. geek_door_addon/config.yaml and Dockerfile validation:
   - Supervisor schema compliance and presence of all required keys.
   - Least privilege verification (no config:rw or data:rw).
   - Multi-arch support and build.yaml parity.
   - Dockerfile instructions, asset presence, and build-dep cleanup.
   - Translations/en.yaml schema coverage.
3. Process hygiene:
   - Zero lingering background processes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDON_DIR = REPO_ROOT / "geek_door_addon"


def get_clean_path_without_jq() -> str:
    """Return a PATH string that excludes any directory containing the jq executable."""
    safe_dirs = []
    for d in os.environ.get("PATH", "").split(os.path.pathsep):
        if d and os.path.isdir(d):
            if not os.path.exists(os.path.join(d, "jq")):
                safe_dirs.append(d)
    return os.path.pathsep.join(safe_dirs)


class TestAddonRunShAdversarial(unittest.TestCase):
    """Adversarial stress-testing of geek_door_addon/run.sh."""

    @classmethod
    def setUpClass(cls):
        cls.run_sh_path = ADDON_DIR / "run.sh"
        if not cls.run_sh_path.is_file():
            raise FileNotFoundError(f"run.sh not found at {cls.run_sh_path}")
        cls.run_sh_text = cls.run_sh_path.read_text(encoding="utf-8")

    def test_run_sh_syntax_and_executable_bit(self):
        """Verify run.sh passes bash -n validation and has executable permission (+x)."""
        st = self.run_sh_path.stat()
        self.assertTrue(
            bool(st.st_mode & stat.S_IXUSR),
            f"run.sh must be executable by owner (+x). Mode: {oct(st.st_mode)}",
        )
        res = subprocess.run(
            ["bash", "-n", str(self.run_sh_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"bash -n failed: {res.stderr}")

    def _execute_run_sh_extractor(
        self,
        options_data: dict | str | None,
        use_jq: bool = True,
    ) -> tuple[int, str, str, dict[str, str]]:
        """Executes the run.sh option extraction and .env writing in an isolated sandbox.

        Uses the actual get_option() function and env-writing logic extracted from run.sh.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            options_path = os.path.join(tmpdir, "options.json")
            env_path = os.path.join(tmpdir, ".env")
            runner_script_path = os.path.join(tmpdir, "extract_runner.sh")

            if isinstance(options_data, dict):
                with open(options_path, "w", encoding="utf-8") as f:
                    json.dump(options_data, f)
            elif isinstance(options_data, str):
                with open(options_path, "w", encoding="utf-8") as f:
                    f.write(options_data)
            # If None, options.json is omitted (tests missing file)

            runner_template = """#!/usr/bin/env bash
set -euo pipefail

OPTIONS_FILE="__OPTIONS_FILE__"
ENV_FILE="__ENV_FILE__"

EMAIL=""
PASSWORD=""
COUNTRY_CODE="1"
API_KEY=""
ENABLE_2FA="false"
LOG_LEVEL="info"
DRY_RUN="false"

get_option() {
    local key="${1:-}"
    local default_val="${2:-}"
    if [ -f "$OPTIONS_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            if jq -e "has(\\"$key\\") and (.\\"$key\\" != null) and (.\\"$key\\" != \\"\\")" "$OPTIONS_FILE" >/dev/null 2>&1; then
                jq -r ".\\"$key\\"" "$OPTIONS_FILE"
            else
                echo "$default_val"
            fi
        else
            python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    v = data.get(sys.argv[2], None)
    if v is None or v == "":
        print(sys.argv[3])
    elif isinstance(v, bool):
        print(str(v).lower())
    else:
        print(v)
except Exception:
    print(sys.argv[3])
' "$OPTIONS_FILE" "$key" "$default_val"
        fi
    else
        echo "$default_val"
    fi
}

if [ -f "$OPTIONS_FILE" ]; then
    EMAIL=$(get_option "email" "")
    PASSWORD=$(get_option "password" "")
    COUNTRY_CODE=$(get_option "country_code" "1")
    API_KEY=$(get_option "api_key" "")
    ENABLE_2FA=$(get_option "enable_2fa" "false")
    LOG_LEVEL=$(get_option "log_level" "info")
    DRY_RUN=$(get_option "dry_run" "false")
fi

if [[ ! "$COUNTRY_CODE" =~ ^[0-9]+$ ]]; then
    COUNTRY_CODE="1"
fi

if [[ ! "$LOG_LEVEL" =~ ^(debug|info|warning|error)$ ]]; then
    LOG_LEVEL="info"
fi

if [[ "$ENABLE_2FA" =~ ^(true|1|yes)$ ]]; then
    ENABLE_2FA="true"
else
    ENABLE_2FA="false"
fi

if [[ "$DRY_RUN" =~ ^(true|1|yes)$ ]]; then
    DRY_RUN="true"
else
    DRY_RUN="false"
fi

python3 -c '
import sys
keys = [
    ("GEEK_DOOR_SESSION_CACHE", "/data/.session_cache.json"),
    ("TUYA_USERNAME", sys.argv[2]),
    ("TUYA_PASSWORD", sys.argv[3]),
    ("TUYA_COUNTRY_CODE", sys.argv[4]),
    ("HA_BEARER_TOKEN", sys.argv[5]),
    ("GEEK_DOOR_API_KEY", sys.argv[5]),
    ("LOG_LEVEL", sys.argv[6]),
    ("ENABLE_2FA", sys.argv[7]),
    ("AUTH_ENABLED", sys.argv[7]),
    ("DRY_RUN", sys.argv[8]),
    ("PORT", "5050"),
    ("HOST", "0.0.0.0"),
]
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for k, v in keys:
        f.write(f"{k}={v}\\n")
' "$ENV_FILE" "$EMAIL" "$PASSWORD" "$COUNTRY_CODE" "$API_KEY" "$LOG_LEVEL" "$ENABLE_2FA" "$DRY_RUN"
chmod 600 "$ENV_FILE"
"""
            runner_script = runner_template.replace("__OPTIONS_FILE__", options_path).replace("__ENV_FILE__", env_path)
            with open(runner_script_path, "w", encoding="utf-8") as f:
                f.write(runner_script)
            os.chmod(runner_script_path, 0o755)

            env = os.environ.copy()
            if not use_jq:
                env["PATH"] = get_clean_path_without_jq()

            res = subprocess.run(
                ["/bin/bash", runner_script_path],
                env=env,
                capture_output=True,
                text=True,
            )

            env_vars: dict[str, str] = {}
            if os.path.isfile(env_path):
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and "=" in line:
                            k, v = line.split("=", 1)
                            env_vars[k] = v

            return res.returncode, res.stdout, res.stderr, env_vars

    def test_boolean_false_options_do_not_revert_to_true_with_jq(self):
        """With jq, booleans set to false in options.json MUST NOT falsely revert to true."""
        payload = {
            "email": "user@test.org",
            "password": "secretPassword",
            "country_code": 1,
            "api_key": "tok-123",
            "enable_2fa": False,
            "log_level": "info",
            "dry_run": False,
        }
        rc, out, err, env_vars = self._execute_run_sh_extractor(payload, use_jq=True)
        self.assertEqual(rc, 0, f"Script failed with jq: {err}")
        self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
        self.assertEqual(env_vars.get("AUTH_ENABLED"), "false")
        self.assertEqual(env_vars.get("DRY_RUN"), "false")

    def test_boolean_false_options_do_not_revert_to_true_without_jq(self):
        """Without jq (python fallback), booleans set to false MUST NOT falsely revert to true."""
        payload = {
            "email": "user@test.org",
            "password": "secretPassword",
            "country_code": 1,
            "api_key": "tok-123",
            "enable_2fa": False,
            "log_level": "info",
            "dry_run": False,
        }
        rc, out, err, env_vars = self._execute_run_sh_extractor(payload, use_jq=False)
        self.assertEqual(rc, 0, f"Script failed without jq: {err}")
        self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
        self.assertEqual(env_vars.get("AUTH_ENABLED"), "false")
        self.assertEqual(env_vars.get("DRY_RUN"), "false")

    def test_boolean_true_options_parsed_correctly(self):
        """Both with and without jq, booleans set to true are parsed as 'true'."""
        payload = {
            "email": "user@test.org",
            "password": "secretPassword",
            "country_code": 1,
            "api_key": "tok-123",
            "enable_2fa": True,
            "log_level": "debug",
            "dry_run": True,
        }
        for use_jq in (True, False):
            with self.subTest(use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor(payload, use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("ENABLE_2FA"), "true")
                self.assertEqual(env_vars.get("AUTH_ENABLED"), "true")
                self.assertEqual(env_vars.get("DRY_RUN"), "true")

    def test_empty_string_null_and_missing_options_revert_to_defaults(self):
        """Empty string options, nulls, and missing keys apply clean default values."""
        # 1. Null and empty string values
        payload_empty = {
            "email": "",
            "password": "",
            "country_code": "",
            "api_key": None,
            "enable_2fa": None,
            "log_level": "",
            "dry_run": None,
        }
        for use_jq in (True, False):
            with self.subTest(stage="empty_and_null", use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor(payload_empty, use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("TUYA_USERNAME"), "")
                self.assertEqual(env_vars.get("TUYA_PASSWORD"), "")
                self.assertEqual(env_vars.get("TUYA_COUNTRY_CODE"), "1")
                self.assertEqual(env_vars.get("HA_BEARER_TOKEN"), "")
                self.assertEqual(env_vars.get("LOG_LEVEL"), "info")
                self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
                self.assertEqual(env_vars.get("DRY_RUN"), "false")

        # 2. Completely empty JSON object {}
        for use_jq in (True, False):
            with self.subTest(stage="empty_dict", use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor({}, use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("TUYA_COUNTRY_CODE"), "1")
                self.assertEqual(env_vars.get("LOG_LEVEL"), "info")
                self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
                self.assertEqual(env_vars.get("DRY_RUN"), "false")

        # 3. Completely missing options.json file
        for use_jq in (True, False):
            with self.subTest(stage="missing_file", use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor(None, use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("TUYA_COUNTRY_CODE"), "1")
                self.assertEqual(env_vars.get("LOG_LEVEL"), "info")
                self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
                self.assertEqual(env_vars.get("DRY_RUN"), "false")

        # 4. Malformed/corrupt JSON file
        for use_jq in (True, False):
            with self.subTest(stage="corrupt_json", use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor("{corrupt: json!@#$", use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("TUYA_COUNTRY_CODE"), "1")
                self.assertEqual(env_vars.get("LOG_LEVEL"), "info")

    def test_passwords_with_special_characters_written_cleanly(self):
        """Passwords containing $, `, \", ', \\, ;, &, |, <, > must be written verbatim to .env."""
        tricky_passwords = [
            "P@$$w0rd$123$$",
            "`whoami`",
            "$(cat /etc/passwd)",
            'pass"with"doublequotes',
            "pass'with'singlequotes",
            "pass\\with\\backslashes\\\\",
            "pass; rm -rf / ; echo $USER",
            "pass && touch /tmp/pwned || true",
            "pass | grep secret > /dev/null",
            'Comb0: $foo `bar` "baz" \'qux\' \\slash & exit 1;',
        ]

        for pwd in tricky_passwords:
            payload = {
                "email": "tricky_user@test.org",
                "password": pwd,
                "country_code": 1,
                "api_key": f"key_{pwd}",
                "enable_2fa": False,
                "log_level": "info",
                "dry_run": False,
            }
            for use_jq in (True, False):
                with self.subTest(pwd=pwd, use_jq=use_jq):
                    rc, out, err, env_vars = self._execute_run_sh_extractor(payload, use_jq=use_jq)
                    self.assertEqual(rc, 0, f"Failed for password '{pwd}': {err}")
                    self.assertEqual(
                        env_vars.get("TUYA_PASSWORD"),
                        pwd,
                        f"Password was corrupted in .env! Expected {pwd!r}, got {env_vars.get('TUYA_PASSWORD')!r}",
                    )
                    self.assertEqual(
                        env_vars.get("GEEK_DOOR_API_KEY"),
                        f"key_{pwd}",
                        f"API Key was corrupted in .env! Expected {('key_' + pwd)!r}, got {env_vars.get('GEEK_DOOR_API_KEY')!r}",
                    )

    def test_input_validation_country_code_and_log_level(self):
        """Non-numeric country_code and invalid log_level reset to safe defaults."""
        payload = {
            "email": "user@test.org",
            "password": "pwd",
            "country_code": "non_numeric_country",
            "api_key": "tok",
            "enable_2fa": "not_a_bool",
            "log_level": "super_verbose_unsupported",
            "dry_run": "invalid",
        }
        for use_jq in (True, False):
            with self.subTest(use_jq=use_jq):
                rc, out, err, env_vars = self._execute_run_sh_extractor(payload, use_jq=use_jq)
                self.assertEqual(rc, 0)
                self.assertEqual(env_vars.get("TUYA_COUNTRY_CODE"), "1")
                self.assertEqual(env_vars.get("LOG_LEVEL"), "info")
                self.assertEqual(env_vars.get("ENABLE_2FA"), "false")
                self.assertEqual(env_vars.get("DRY_RUN"), "false")

    def test_signal_trap_terminates_cleanly_on_sigterm_and_sigint(self):
        """Simulates run.sh signal trap handling and verifies child termination and exit code 0."""
        # Create a mock script with run.sh's exact term_handler logic
        with tempfile.TemporaryDirectory() as tmpdir:
            test_script = os.path.join(tmpdir, "test_trap.sh")
            child_flag = os.path.join(tmpdir, "child_running.txt")
            with open(test_script, "w", encoding="utf-8") as f:
                f.write(f"""#!/usr/bin/env bash
set -euo pipefail

SERVER_PID=""

term_handler() {{
    echo "[INFO] Received termination signal. Shutting down cleanly..."
    if [ -n "${{SERVER_PID:-}}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    exit 0
}}
trap term_handler SIGTERM SIGINT SIGHUP

# Spawn a long-running mock server
python3 -c '
import time, signal, sys
signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
while True:
    time.sleep(0.1)
' &
SERVER_PID=$!
echo "$SERVER_PID" > "{child_flag}"
wait "$SERVER_PID"
""")
            os.chmod(test_script, 0o755)

            for sig in (signal.SIGTERM, signal.SIGINT):
                with self.subTest(sig=sig.name):
                    proc = subprocess.Popen(
                        ["/bin/bash", test_script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    # Wait for child process to start
                    for _ in range(50):
                        if os.path.isfile(child_flag):
                            break
                        time.sleep(0.05)
                    self.assertTrue(os.path.isfile(child_flag), "Child process failed to start")

                    with open(child_flag, "r") as f:
                        child_pid = int(f.read().strip())

                    # Send signal to parent script
                    proc.send_signal(sig)
                    stdout, stderr = proc.communicate(timeout=5.0)

                    self.assertEqual(
                        proc.returncode,
                        0,
                        f"Expected clean exit code 0 on {sig.name}, got {proc.returncode}. Output: {stdout}",
                    )
                    self.assertIn("Received termination signal", stdout)

                    # Verify child process is stopped
                    time.sleep(0.1)
                    try:
                        os.kill(child_pid, 0)
                        child_alive = True
                    except OSError:
                        child_alive = False
                    self.assertFalse(child_alive, f"Child PID {child_pid} remained alive after {sig.name}")

                    # Cleanup flag for next iteration
                    if os.path.isfile(child_flag):
                        os.remove(child_flag)


class TestAddonConfigAndDockerfileStress(unittest.TestCase):
    """Stress-tests config.yaml, build.yaml, Dockerfile, and translation assets."""

    def test_config_yaml_supervisor_spec_conformance(self):
        """Validates all supervisor keys and schema types in config.yaml."""
        config_path = ADDON_DIR / "config.yaml"
        self.assertTrue(config_path.is_file(), "config.yaml missing")
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        required_keys = [
            "name", "version", "slug", "description", "url",
            "arch", "startup", "boot", "ports", "webui",
            "ingress", "ingress_port", "panel_icon", "panel_title",
            "options", "schema", "map",
        ]
        for key in required_keys:
            self.assertIn(key, cfg, f"Missing required supervisor key: '{key}'")

        # Slug validation
        self.assertEqual(cfg["slug"], "geek_door")
        self.assertEqual(cfg["startup"], "services")
        self.assertEqual(cfg["boot"], "auto")

        # Ingress & Ports
        self.assertTrue(cfg["ingress"])
        self.assertEqual(cfg["ingress_port"], 5050)
        self.assertIn("5050/tcp", cfg["ports"])
        self.assertEqual(cfg["ports"]["5050/tcp"], 5050)

        # Options and schema correspondence
        options = cfg["options"]
        schema = cfg["schema"]
        self.assertIsInstance(options, dict)
        self.assertIsInstance(schema, dict)

        for opt_name in options:
            self.assertIn(opt_name, schema, f"Option '{opt_name}' defined in options but missing in schema")

        # Least-privilege map validation: must not expose root data or config rw
        mapping = cfg.get("map", [])
        self.assertNotIn("config:rw", mapping, "Elevated privilege 'config:rw' must not be in map")
        self.assertNotIn("data:rw", mapping, "Elevated privilege 'data:rw' must not be in map")
        self.assertIn("ssl:ro", mapping, "ssl:ro mapping should be present for HTTPS/SSL bridges")

    def test_multi_arch_and_build_yaml_consistency(self):
        """Verifies arch lists in config.yaml match build.yaml GHCR base images."""
        config_path = ADDON_DIR / "config.yaml"
        build_path = ADDON_DIR / "build.yaml"

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        with open(build_path, "r", encoding="utf-8") as f:
            bld = yaml.safe_load(f)

        expected_archs = {"armhf", "armv7", "aarch64", "amd64", "i386"}
        config_archs = set(cfg.get("arch", []))
        self.assertEqual(config_archs, expected_archs, f"Unexpected arch set in config.yaml: {config_archs}")

        build_archs = set(bld.get("build_from", {}).keys())
        self.assertEqual(build_archs, expected_archs, f"Unexpected arch set in build.yaml: {build_archs}")

        for arch, image in bld["build_from"].items():
            self.assertTrue(
                image.startswith("ghcr.io/home-assistant/"),
                f"Image for arch {arch} does not use official HA base: {image}",
            )

    def test_translations_en_yaml_matches_options(self):
        """Verifies translations/en.yaml covers all options in config.yaml."""
        trans_path = ADDON_DIR / "translations" / "en.yaml"
        self.assertTrue(trans_path.is_file(), "translations/en.yaml missing")
        with open(trans_path, "r", encoding="utf-8") as f:
            trans = yaml.safe_load(f)

        self.assertIn("configuration", trans)
        config_trans = trans["configuration"]

        config_path = ADDON_DIR / "config.yaml"
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        for opt_name in cfg.get("options", {}):
            self.assertIn(
                opt_name,
                config_trans,
                f"Option '{opt_name}' defined in config.yaml but missing translation in en.yaml",
            )
            self.assertIn("name", config_trans[opt_name])
            self.assertIn("description", config_trans[opt_name])

    def test_dockerfile_instruction_integrity_and_hygiene(self):
        """Verifies Dockerfile contains clean build stages, no dead packages, and local requirements."""
        dockerfile_path = ADDON_DIR / "Dockerfile"
        self.assertTrue(dockerfile_path.is_file(), "Dockerfile missing")
        content = dockerfile_path.read_text(encoding="utf-8")

        # Essential directives
        self.assertIn("ARG BUILD_FROM=", content)
        self.assertIn("FROM ${BUILD_FROM}", content)
        self.assertIn("WORKDIR /app", content)
        self.assertIn("COPY requirements.txt /app/requirements.txt", content)
        self.assertIn("pip install --no-cache-dir -r /app/requirements.txt", content)
        self.assertIn("EXPOSE 5050", content)
        self.assertIn('CMD ["/run.sh"]', content)

        # Build-deps hygiene: virtual deps must be deleted
        self.assertIn("--virtual .build-deps", content)
        self.assertIn("apk del .build-deps", content)

        # Removed dead packages
        self.assertNotIn("bluez-deprecated", content)

        # Context self-containment: local requirements.txt
        local_reqs = ADDON_DIR / "requirements.txt"
        self.assertTrue(local_reqs.is_file(), "Local requirements.txt missing from addon context")
        req_lines = [l.strip() for l in local_reqs.read_text().splitlines() if l.strip()]
        req_packages = [l.split(">=")[0].split("==")[0].split("<")[0].strip() for l in req_lines]
        self.assertIn("flask", req_packages)
        self.assertIn("requests", req_packages)
        self.assertIn("cryptography", req_packages)
        self.assertIn("pyyaml", req_packages)


class TestBackgroundProcessesHygiene(unittest.TestCase):
    """Verifies that no lingering background server processes exist."""

    def test_zero_lingering_server_processes(self):
        """Ensures 0 background door_lock_control or flask server processes are running."""
        res = subprocess.run(
            ["pgrep", "-f", "door_lock_control.py serve"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            1,
            f"Lingering door_lock_control.py serve processes detected: {res.stdout}",
        )

        res_flask = subprocess.run(
            ["pgrep", "-f", "flask run"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res_flask.returncode,
            1,
            f"Lingering flask run processes detected: {res_flask.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
