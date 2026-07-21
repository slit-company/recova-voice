"""Hermetic contracts for the ephemeral Jambonz time-series adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
ADAPTER = ROOT / "recova-time-series.js"
PATCHES = ROOT / "patches" / "node"


class NoStorageAdapterTests(unittest.TestCase):
    def test_runtime_adapter_has_no_persistence_side_effects(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is unavailable")
        script = """
const factory = require(process.argv[1]);
const adapter = factory();
(async () => {
  const names = ['writeCallCount', 'writeCallCountSP', 'writeCallCountApp',
    'writeCdrs', 'writeAlerts', 'writeSystemAlerts'];
  for (const name of names) {
    if (typeof adapter[name] !== 'function') throw new Error(`missing ${name}`);
    if (await adapter[name]({secret: 'must-not-be-written'}) !== undefined) {
      throw new Error(`${name} must not return persisted data`);
    }
  }
  const rows = await adapter.queryCdrs({secret: 'must-not-be-read'});
  if (!Array.isArray(rows) || rows.length !== 0) throw new Error('queryCdrs must be empty');
  if (!Object.isFrozen(adapter.AlertType)) throw new Error('AlertType must be immutable');
  process.stdout.write(JSON.stringify({writes: names.length, rows: rows.length}));
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(
            [node, "-e", script, str(ADAPTER)],
            env={**os.environ, "RECOVA_EPHEMERAL_NO_STORAGE": "1"},
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"writes": 6, "rows": 0})

    def test_every_persistent_writer_is_replaced_in_sealed_patches(self) -> None:
        expected = {
            "jambonz-feature-server.patch": ("./recova-time-series", 3),
            "jambonz-api-server.patch": ("./lib/recova-time-series", 1),
            "sbc-inbound.patch": ("./lib/recova-time-series", 1),
            "sbc-outbound.patch": ("./lib/recova-time-series", 1),
            "sbc-sip-sidecar.patch": ("./lib/recova-time-series", 1),
        }
        canonical = ADAPTER.read_text(encoding="utf-8")
        for name, (replacement, minimum) in expected.items():
            patch = (PATCHES / name).read_text(encoding="utf-8")
            self.assertGreaterEqual(patch.count(replacement), minimum, name)
            self.assertIn("RECOVA_EPHEMERAL_NO_STORAGE", patch, name)
            self.assertIn("writeCdrs: noop", patch, name)
            self.assertIn("queryCdrs: empty", patch, name)
            self.assertIn("writeSystemAlerts: noop", patch, name)
            self.assertIn(canonical.splitlines()[-2], patch, name)
        api_patch = (PATCHES / "jambonz-api-server.patch").read_text(
            encoding="utf-8"
        )
        self.assertIn("'HTTP/1.1 403 Forbidden", api_patch)
        self.assertIn("recovaEphemeralNoStorage", api_patch)

    def test_storage_mode_is_explicit_and_fail_closed(self) -> None:
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertIn("RECOVA_EPHEMERAL_NO_STORAGE !== '1'", source)
        self.assertNotIn("fetch(", source)
        self.assertNotIn("http", source.lower())
        self.assertNotIn("setTimeout", source)
        self.assertNotIn("setInterval", source)


if __name__ == "__main__":
    unittest.main()
