"""AI models in the release ledger (zmodel.py, zenos-decide "model" and "model_api"): a model kept on the PC is loaded
only when every file is the released one, and an API model is called only at the identity pinned in the ledger.
Three audit nodes run on 127.0.0.1 in this process, as in test_supply.py."""
import json, os, shutil, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin"), str(REPO / "tests")]
import zsupply, zmodel                                           # noqa: E402
import test_supply                                               # noqa: E402  (its audit nodes, not its cases)


def make_model(d, name, weights=None):
    weights = weights or (b"\x00\x01weights of " + name.encode()) * 64
    m = d / name
    (m / "adapter").mkdir(parents=True)
    (m / "model.safetensors").write_bytes(weights)
    (m / "tokenizer.json").write_text('{"vocab": {"a": 0, "b": 1}}')
    (m / "config.json").write_text('{"layers": 2}')
    (m / "adapter" / "lora.safetensors").write_bytes(b"lora" * 32)
    return m


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class Models(unittest.TestCase):
    # the audit nodes, officers and publishing of the package ledger's test, not its test cases
    setUpClass = classmethod(test_supply.ReleaseLedger.setUpClass.__func__)
    publish = test_supply.ReleaseLedger.publish

    def conf(self, required=2, mode="enforce"):
        return {"mode": mode, "required": required, "ring": 1, "nodes": self.pcnodes, "keys": self.keys}

    def released(self, name, signers=("ito", "kato"), max_level=2, nodes=(0, 1, 2)):
        src = make_model(self.tmp, name)
        rec = {"manifest": zmodel.manifest(src, name, "1.0", "example lab", "https://example.invalid/" + name,
                                           "Apache-2.0", max_level)}
        for n in signers:
            zsupply.sign(rec, self.officers[n], n)
        self.publish(rec, list(nodes))
        p = self.tmp / f"{name}.record.json"
        p.write_text(json.dumps(rec))
        return src, p, rec

    def installed(self, name, **kw):
        import zenos_model
        src, rec_path, rec = self.released(name, **kw)
        dest = self.tmp / "models"
        return zenos_model.install(src, rec_path, dest, self.conf()), rec

    def test_a_released_model_loads(self):
        folder, rec = self.installed("whisper-small")
        self.assertEqual(zmodel.check(folder, 2, self.conf()), (True, None))
        self.assertIn("adapter/lora.safetensors", rec["manifest"]["files"])
        self.assertEqual(zmodel.offline_check(folder, self.keys, 2), [])

    def test_one_changed_weight_is_refused(self):
        """a few bytes of the weights rewritten (the file looks the same): the model is not loaded"""
        folder, _ = self.installed("ocr-base")
        w = folder / "model.safetensors"
        b = bytearray(w.read_bytes())
        b[10] ^= 0x01
        w.write_bytes(bytes(b))
        self.assertEqual(zmodel.check(folder, 1, self.conf()), (False, "files"))
        self.assertEqual([f["detail"] for f in zmodel.offline_check(folder, self.keys, 2)], ["not the released file"])

    def test_an_added_or_missing_file_is_refused(self):
        folder, _ = self.installed("summarizer")
        (folder / "adapter" / "extra.safetensors").write_bytes(b"a second adapter")
        self.assertEqual(zmodel.check(folder, 1, self.conf())[0], False)
        (folder / "adapter" / "extra.safetensors").unlink()
        (folder / "tokenizer.json").unlink()
        self.assertEqual(zmodel.check(folder, 1, self.conf()), (False, "files"))

    def test_a_link_is_refused(self):
        folder, _ = self.installed("linked")
        (folder / "config.json").unlink()
        (folder / "config.json").symlink_to(self.tmp / "elsewhere.json")
        self.assertFalse(zmodel.check(folder, 1, self.conf())[0])

    def test_one_officer_is_not_enough(self):
        import zenos_model
        src, rec_path, _ = self.released("one-key", signers=("ito",))
        with self.assertRaises(zmodel.Refused):
            zenos_model.install(src, rec_path, self.tmp / "models", self.conf())
        # put in place by hand (as if copied by someone with root): the decision still refuses it
        dest = self.tmp / "models" / "one-key-1.0"
        shutil.copytree(src, dest)
        shutil.copy(rec_path, dest / zmodel.RECORD)
        self.assertEqual(zmodel.check(dest, 1, self.conf()), (False, "signatures"))

    def test_one_audit_node_is_not_enough(self):
        import zenos_model
        src, rec_path, _ = self.released("one-node", nodes=(0,))
        with self.assertRaises(zmodel.Refused):
            zenos_model.install(src, rec_path, self.tmp / "models", self.conf())

    def test_data_above_the_models_level_is_refused(self):
        folder, _ = self.installed("level-two", max_level=2)
        self.assertEqual(zmodel.check(folder, 3, self.conf()), (False, "level"))

    def test_a_model_without_a_record_is_refused(self):
        folder = make_model(self.tmp / "models", "unreleased")
        self.assertFalse(zmodel.check(folder, 0, self.conf())[0])
        self.assertEqual(zmodel.offline_check(folder, self.keys, 2)[0]["kind"], "model-unrecorded")

    def test_a_package_record_cannot_stand_in_for_a_model(self):
        """a record signed and held by the ledger, but as a package, does not let the model folder be loaded"""
        src = make_model(self.tmp, "kind-check")
        m = dict(zmodel.manifest(src, "kind-check", "1.0", "lab", "", "MIT", 2), kind="zenos-release")
        rec = {"manifest": m}
        for n in ("ito", "kato"):
            zsupply.sign(rec, self.officers[n], n)
        self.publish(rec, [0, 1, 2])
        dest = self.tmp / "models" / "kind-check-1.0"
        shutil.copytree(src, dest)
        (dest / zmodel.RECORD).write_text(json.dumps(rec))
        self.assertFalse(zmodel.check(dest, 0, self.conf())[0])

    def test_the_watcher_quarantines_a_changed_model(self):
        import zenos_supplywatch as W
        folder, _ = self.installed("watched")
        old = (W.MODELS, W.QUARANTINE)
        W.MODELS, W.QUARANTINE = str(folder.parent), self.tmp / "quarantine"
        try:
            self.assertEqual(W.inspect_model(str(folder / "config.json"), self.conf()), "ok")
            (folder / "config.json").write_text('{"layers": 2, "trigger": true}')
            self.assertEqual(W.inspect_model(str(folder / "config.json"), self.conf()), "quarantined")
            self.assertFalse(folder.exists())
            self.assertTrue(any("model-watched" in p.name for p in W.QUARANTINE.iterdir()))
            stray = Path(W.MODELS) / "stray.bin"
            stray.write_bytes(b"not a model folder")
            self.assertEqual(W.inspect_model(str(stray), self.conf()), "quarantined")
        finally:
            W.MODELS, W.QUARANTINE = old

    # ---------------- API models ----------------
    def pin(self, conf, signers=("ito", "kato"), max_level=1):
        rec = {"manifest": zmodel.api_manifest(conf, "release officers", max_level)}
        for n in signers:
            zsupply.sign(rec, self.officers[n], n)
        self.publish(rec, [0, 1, 2])

    def test_an_api_model_is_called_only_at_its_pinned_version(self):
        conf = {"name": "a", "kind": "anthropic", "model": "claude-opus-5-5"}
        self.assertEqual(zmodel.check_api(conf, 0, self.conf())[0], False)          # not pinned yet
        self.pin(conf)
        self.assertEqual(zmodel.check_api(conf, 1, self.conf()), (True, None))
        self.assertFalse(zmodel.check_api(dict(conf, model="claude-opus-5-6"), 1, self.conf())[0])
        self.assertFalse(zmodel.check_api(dict(conf, url="https://elsewhere.example/v1"), 1, self.conf())[0])
        for other in ("http://api.anthropic.com", "https://api.anthropic.com:8443", "https://api.anthropic.com/proxy",
                      "https://x@api.anthropic.com", "https://api.anthropic.com/?u=evil.example"):
            self.assertFalse(zmodel.check_api(dict(conf, url=other), 1, self.conf())[0], other)   # the whole address
        self.assertEqual(zmodel.check_api(dict(conf, url="https://API.anthropic.com/"), 1, self.conf()), (True, None))
        self.assertEqual(zmodel.check_api(conf, 2, self.conf()), (False, "level"))

    def test_a_refused_provider_stays_refused_even_when_pinned(self):
        conf = {"name": "q", "kind": "openai-compatible", "model": "qwen-max", "url": "https://dashscope.aliyuncs.com/v1"}
        self.pin(conf)
        self.assertEqual(zmodel.check_api(conf, 0, self.conf())[0], False)
        self.assertEqual(zmodel.check_api(conf, 0, self.conf(mode="off")), (False, "denied"))


if __name__ == "__main__":
    unittest.main()
