#!/usr/bin/env python3
"""GeekSmart Door Lock E2E Test Suite Runner.

Supports running tests by tier, milestone, or module, with optional live production verification.
"""

import argparse
import os
import sys
import time
import unittest

# Ensure repo root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def filter_suite(suite, pattern):
    """Filters a unittest.TestSuite recursively by test method name or docstring."""
    filtered = unittest.TestSuite()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            sub = filter_suite(item, pattern)
            if sub.countTestCases() > 0:
                filtered.addTest(sub)
        elif isinstance(item, unittest.TestCase):
            test_id = item.id()
            if pattern.lower() in test_id.lower():
                filtered.addTest(item)
    return filtered


def run_tests():
    parser = argparse.ArgumentParser(description="GeekSmart Door Lock E2E Test Suite Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run tests for a specific tier (1-4)")
    parser.add_argument("--milestone", type=int, choices=[1, 2, 3, 4, 6, 11, 12], help="Run tests for a specific milestone (1-4, 6, 11, 12)")

    parser.add_argument("--live", action="store_true", help="Enable live read-only verification against production using .env")
    parser.add_argument("--module", type=str, help="Run specific test module (e.g. crypto, auth, discovery, safety, control, gateway)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Verbose test execution output")
    args = parser.parse_args()

    if args.live:
        os.environ["RUN_LIVE_TESTS"] = "1"
        print("[INFO] Live test execution enabled (--live)")

    loader = unittest.TestLoader()
    tests_dir = os.path.dirname(os.path.abspath(__file__))

    # Module selection
    if args.module:
        module_name = f"tests.test_{args.module.replace('test_', '')}"
        try:
            suite = loader.loadTestsFromName(module_name)
        except Exception as exc:
            print(f"[ERROR] Failed to load module {module_name}: {exc}")
            sys.exit(1)
    else:
        suite = loader.discover(start_dir=tests_dir, pattern="test_*.py")

    # Milestone filtering
    if args.milestone:
        if args.milestone == 1:
            # Milestone 1: Crypto, Auth, Discovery
            m1_suite = unittest.TestSuite()
            for mod in ["tests.test_crypto", "tests.test_auth", "tests.test_discovery"]:
                try:
                    m1_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m1_suite
        elif args.milestone == 2:
            # Milestone 2: Control & Safety Barrier
            m2_suite = unittest.TestSuite()
            for mod in ["tests.test_control", "tests.test_safety"]:
                try:
                    m2_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m2_suite
        elif args.milestone == 3:
            # Milestone 3: Gateway, Tuya & Daemon scenarios
            m3_suite = unittest.TestSuite()
            for mod in ["tests.test_gateway", "tests.test_tuya"]:
                try:
                    m3_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m3_suite
        elif args.milestone == 4:
            # Milestone 4: Local Flask Mobile Dashboard Server
            m4_suite = unittest.TestSuite()
            for mod in ["tests.test_server"]:
                try:
                    m4_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m4_suite
        elif args.milestone == 6:
            # Milestone 6: Security Audit & Hardening
            m6_suite = unittest.TestSuite()
            for mod in [
                "tests.test_security_audit",
                "tests.test_server_security",
                "tests.test_adversarial_security",
                "tests.test_adversarial_safety",
            ]:
                try:
                    m6_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m6_suite
        elif args.milestone == 11:
            # Milestone 11: Core Lock Engine, Direct BLE GATT & HACS / Add-on Integration
            m11_suite = unittest.TestSuite()
            for mod in [
                "tests.test_lock_engine",
                "tests.test_ble_gatt",
                "tests.test_hacs_integration",
                "tests.test_challenger_m11_lock_engine",
                "tests.test_challenger_m11_ble_hacs",
            ]:
                try:
                    m11_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m11_suite
        elif args.milestone == 12:
            # Milestone 12: Ecosystem Audit & Universal Hardening
            m12_suite = unittest.TestSuite()
            for mod in [
                "tests.test_m12_audit_hardening",
            ]:
                try:
                    m12_suite.addTests(loader.loadTestsFromName(mod))
                except Exception as exc:
                    print(f"[WARNING] Could not load {mod}: {exc}")
            suite = m12_suite


    # Tier filtering
    if args.tier:
        tier_pattern = f"_t{args.tier}_"
        filtered_suite = filter_suite(suite, tier_pattern)
        print(f"[INFO] Filtering for Tier {args.tier} tests (pattern: '{tier_pattern}'): {filtered_suite.countTestCases()} test cases found.")
        suite = filtered_suite

    total_cases = suite.countTestCases()
    print("=" * 70)
    print("GEEKSMART DOOR LOCK TEST SUITE RUNNER")
    print(f"Total Test Cases Selected: {total_cases}")
    print("=" * 70)

    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    start_time = time.time()
    result = runner.run(suite)
    duration = time.time() - start_time

    print("=" * 70)
    print("TEST SUMMARY")
    print(f"Executed: {result.testsRun} in {duration:.3f}s")
    print(f"Passed:   {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors:   {len(result.errors)}")
    print(f"Skipped:  {len(result.skipped)}")
    print("=" * 70)

    if result.wasSuccessful():
        print("RESULT: SUCCESS (Exit Code 0)")
        sys.exit(0)
    else:
        print("RESULT: FAILURE (Exit Code 1)")
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
