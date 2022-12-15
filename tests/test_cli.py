import os
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, NamedTuple, Optional
import unittest

# Test runner decorator: Runs the test as a set of SubTests,
def run_sub_tests_with_dataset(dataset: Dict[str, Any]):
    def real_decorator(function: Callable[[unittest.TestCase, Any], None]):
        def wrapper(test_cls: unittest.TestCase):
            for case, data in dataset.items():
                with test_cls.subTest(case=case):
                    function(test_cls, data)
        return wrapper
    return real_decorator


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.cwd = self.tempdir.name

    def tearDown(self):
        self.tempdir.cleanup()

    def assertStartsWith(self, haystack:str,  needle: str):
        if not haystack.startswith(needle):
            raise AssertionError(
                f"Expected '{needle}...', got '{haystack[:len(needle)]}...'"
            )

    def _run(self, args: str, expected_out:Optional[str]="", expected_err:Optional[str]=None) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            args=["tufrepo"] + args.split(),
            capture_output=True, 
            cwd=self.cwd,
            text=True
        )
        if expected_out is not None:
           self.assertEqual(proc.stdout, expected_out)
        if expected_err is not None:
            if proc.stderr != expected_err:
                print(proc.stderr)
            self.assertEqual(proc.stderr, expected_err)
            self.assertEqual(proc.returncode, 1)
        else:
            self.assertEqual(proc.returncode, 0)

        return proc
 
    Data = NamedTuple("Data", [("argv", str), ("expect_out", str)])
    valid_commands: Dict[str, Data] = {
        "no args": Data("", "Usage: tufrepo [OPTIONS] COMMAND [ARGS]"),
        "help": Data("--help", "Usage: tufrepo [OPTIONS] COMMAND [ARGS]"),
        "verify": Data("verify --help", "Usage: tufrepo verify "),
        "sign": Data("sign --help", "Usage: tufrepo sign "),
        "snapshot": Data ("snapshot --help", "Usage: tufrepo snapshot "),
        "edit 1": Data("edit", "Usage: tufrepo edit "),
        "edit 2": Data("edit --help", "Usage: tufrepo edit "),
        "add-delegation": Data("edit x add-delegation --help", "Usage: tufrepo edit ROLE add-delegation "),
        "add-key": Data("edit x add-key --help", "Usage: tufrepo edit ROLE add-key "),
        "add-target": Data("add-target --help", "Usage: tufrepo add-target "),
        "init": Data("edit x init --help", "Usage: tufrepo edit ROLE init "),
        "remove-delegation": Data("edit x remove-delegation --help", "Usage: tufrepo edit ROLE remove-delegation "),
        "remove-key": Data("edit x remove-key --help", "Usage: tufrepo edit ROLE remove-key "),
        "set-expiry": Data("edit x set-expiry --help", "Usage: tufrepo edit ROLE set-expiry "),
        "set-threshold": Data("edit x set-threshold --help", "Usage: tufrepo edit ROLE set-threshold "),
        "touch": Data("edit x touch --help", "Usage: tufrepo edit ROLE touch "),
    }
    @run_sub_tests_with_dataset(valid_commands)
    def test_basics(self, data: Data):
        """Test (mostly help) commands that work without metadata"""
        proc = self._run(data.argv, expected_out=None)
        self.assertStartsWith(proc.stdout, data.expect_out)

    def test_repo_manual_init(self):
        """Test (roughly) the tutorial from README"""
        subprocess.run(["git", "init", "."], cwd=self.cwd, capture_output=True)
        subprocess.run(["git", "config", "--local", "user.name", "test"], cwd=self.cwd)
        subprocess.run(["git", "config", "--local", "user.email", "test@example.com"], cwd=self.cwd)

        # Create initial metadata
        self._run("edit root init")
        self._run("edit root add-key root")
        self._run("edit root add-key snapshot")
        self._run("edit root add-key timestamp")
        self._run("edit root add-key targets")
        self._run("edit timestamp init")
        self._run("edit snapshot init")
        self._run("edit targets init")
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Initial metadata"], cwd=self.cwd, capture_output=True)

        self.assertIn("Metadata with 0 delegated targets verified", proc.stdout)
        self.assertIn("Keyring contains keys for [root, snapshot, targets, timestamp]", proc.stdout)
        files = {".git", "1.root.json", "1.snapshot.json", "1.targets.json", "private_keys", "timestamp.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

    def test_repo_management(self):
        """Test (roughly) the tutorial from README"""
        subprocess.run(["git", "init", "."], cwd=self.cwd, capture_output=True)
        subprocess.run(["git", "config", "--local", "user.name", "test"], cwd=self.cwd)
        subprocess.run(["git", "config", "--local", "user.email", "test@example.com"], cwd=self.cwd)

        # Create initial metadata
        self._run("init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Initial metadata"], cwd=self.cwd, capture_output=True)

        self.assertIn("Metadata with 0 delegated targets verified", proc.stdout)
        self.assertIn("Keyring contains keys for [root, snapshot, targets, timestamp]", proc.stdout)
        files = {".git", "1.root.json", "1.snapshot.json", "1.targets.json", "private_keys", "timestamp.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        self._run("edit root add-key root")
        self._run("edit root set-threshold root 2")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "root edit"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")
        files.add("2.root.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add new role, delegate to role
        self._run("edit targets add-delegation --path 'files/*' role1")
        self._run("edit targets add-key role1")
        self._run("edit role1 init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add role, delegate"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")
        files |= { "2.targets.json", "1.role1.json" }
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Update snapshot
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "snapshot"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files -= { "1.snapshot.json", "1.targets.json" }
        files.add("2.snapshot.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Update snapshot when it's not needed (expect nothing to happen)
        self._run("snapshot")
        proc = subprocess.run(["git", "diff", "--quiet"], cwd=self.cwd)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add target to role1 (don't add file to git)
        self._run(
            "add-target --role role1 --no-target-in-repo files/timestamp.json timestamp.json",
            "Added 'files/timestamp.json' as target to role 'role1'\n"
        )

        # Add target to role1 (also add target and hash-prefixed symlinks to git)
        with open(f"{self.cwd}/new-target", "w") as f:
            f.write("hello")
        self._run(
            "add-target --role role1 files/new-target ./new-target",
            "Added 'files/new-target' as target to role 'role1'\n"
        )

        # Add target to role1 using delegation tree
        self._run(
            "add-target --role role1 files/newer-target ./new-target",
            "Added 'files/newer-target' as target to role 'role1'\n"
        )

        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add target files"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files |= { "2.role1.json", "new-target", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824.new-target" }
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # update snapshot
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add target"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files -= { "1.role1.json", "2.snapshot.json" }
        files.add("3.snapshot.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Make a timestamp update
        self._run("edit timestamp touch")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add target"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Remove a target (without delegation search), update snapshot
        proc = self._run("remove-target --no-follow-delegations --role role1 files/new-target", expected_out=None)
        self.assertStartsWith(proc.stdout, "Removed files/new-target ")
        self._run("snapshot")
        subprocess.run(["git", "commit", "-a", "-m", "Remove target"], cwd=self.cwd, capture_output=True)

        files -= { "3.snapshot.json", "2.role1.json" }
        files |= { "4.snapshot.json", "3.role1.json" }
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Remove delegation, remove delegated role
        self._run("edit targets remove-delegation role1")
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "rm", "3.role1.json"], cwd=self.cwd, capture_output=True)
        subprocess.run(["git", "commit", "-a", "-m", "Remove delegation"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")
        files -= { "4.snapshot.json", "2.targets.json", "3.role1.json" }
        files |= { "5.snapshot.json", "3.targets.json" }
        self.assertEqual(set(os.listdir(self.cwd)), files)

    def test_targets_changes(self):
        """Test multiple changes in targets delegations"""
        subprocess.run(["git", "init", "."], cwd=self.cwd, capture_output=True)
        subprocess.run(["git", "config", "--local", "user.name", "test"], cwd=self.cwd)
        subprocess.run(["git", "config", "--local", "user.email", "test@example.com"], cwd=self.cwd)

        # Create initial metadata
        self._run("init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Initial metadata"], cwd=self.cwd, capture_output=True)

        self.assertIn("Metadata with 0 delegated targets verified", proc.stdout)
        self.assertIn("Keyring contains keys for [root, snapshot, targets, timestamp]", proc.stdout)
        files = {".git", "1.root.json", "1.snapshot.json", "1.targets.json", "private_keys", "timestamp.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add new role, delegate to role
        self._run("edit targets add-delegation --path 'files/*' role1")
        self._run("edit targets add-key role1")
        self._run("edit role1 init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add role, delegate"], cwd=self.cwd, capture_output=True)

        # 1.targets.json is used for verification until a snapshot update.
        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")
        files |= { "2.targets.json", "1.role1.json" }
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Update snapshot
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "snapshot"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files -= { "1.snapshot.json", "1.targets.json" }
        files.add("2.snapshot.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add another role with multiple hash prefixes
        self._run("edit targets add-delegation --hash-prefix 00 --hash-prefix 01 role2")
        self._run("edit targets add-key role2")
        self._run("edit role2 init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Add second role, delegate"], cwd=self.cwd, capture_output=True)

        # 2.targets.json is used for verification until a snapshot update.
        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files |= {"3.targets.json", "1.role2.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Update snapshot
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "snapshot"], cwd=self.cwd, capture_output=True)

        self.assertStartsWith(proc.stdout, "Metadata with 2 delegated targets verified")
        files -= {"2.snapshot.json", "2.targets.json"}
        files.add("3.snapshot.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add succinct hash delegation removing all other delegated role info.
        self._run("edit targets add-delegation --succinct 4 bin")
        proc = self._run("verify", expected_out=None)

        # 3.targets.json is used for verification until a snapshot update.
        # Also, no delegated bin files were yet initialized.
        self.assertStartsWith(proc.stdout, "Metadata with 2 delegated targets verified")
        files.add("4.targets.json")
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add a new key that will be used for succinct hash bin delegation.
        self._run("edit targets add-key")

        # Initialize delegated bin files based on the info in targets.
        self._run("init-succinct-roles targets")

        # Update snapshot to use the 4.targets.json with the succint roles info.
        self._run("snapshot")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "snapshot"], cwd=self.cwd, capture_output=True)

        # Only the delegated bins are considered as delegated targets.
        self.assertStartsWith(proc.stdout, "Metadata with 4 delegated targets verified")
        files -= {"3.snapshot.json", "3.targets.json"}
        files |= {"4.snapshot.json", "1.bin-0.json", "1.bin-1.json", "1.bin-2.json", "1.bin-3.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Add a target to a delegated bin (use timestamp as content)
        self._run(
            "add-target --no-target-in-repo target/path timestamp.json",
            "Added 'target/path' as target to role 'bin-1'\n"
        )
        self._run("snapshot")
        subprocess.run(["git", "commit", "-a", "-m", "add target to delegated bin"], cwd=self.cwd, capture_output=True)

        # expect that target was added to bin-1 because of delegation
        files -= {"4.snapshot.json", "1.bin-1.json"}
        files |= {"5.snapshot.json", "2.bin-1.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Remove target using delegation search
        proc = self._run("remove-target target/path", None)
        self.assertStartsWith(proc.stdout, "Removed target/path from role bin-1")
        self._run("snapshot")
        subprocess.run(["git", "commit", "-a", "-m", "Remove target from delegated bin"], cwd=self.cwd, capture_output=True)

        # expect that target was removed from bin-1 because of delegation
        files -= {"5.snapshot.json", "2.bin-1.json"}
        files |= {"6.snapshot.json", "3.bin-1.json"}

        # Delegate to a new role in targets removing the succinct hash info.
        self._run("edit targets add-delegation --path 'files/*' role3")
        self._run("edit targets add-key role3")
        self._run("edit role3 init")

        # Update snapshot to use new targets metadata without the succint info.
        self._run("snapshot")

        files -= {"6.snapshot.json", "4.targets.json"}
        files |= {"7.snapshot.json", "5.targets.json", "1.role3.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Remove all bins as "targets" doesn't delegate to them anymore.
        subprocess.run(
            ["rm",  "1.bin-0.json", "2.bin-1.json", "1.bin-2.json", "1.bin-3.json"],
            cwd=self.cwd,
            capture_output=True
        )

        proc = self._run("verify", expected_out=None)
        subprocess.run([
            "git",
            "commit", "-a", "-m", "Add role, delegate and remove succinct info"],
            cwd=self.cwd,
            capture_output=True,
        )

        self.assertStartsWith(proc.stdout, "Metadata with 1 delegated targets verified")
        files -= {"1.bin-0.json", "2.bin-1.json", "1.bin-2.json", "1.bin-3.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        #### Cases that throw exception ####
        # Adding standard delegation and succinct hash bin delegation at once.
        self._run(
            "edit targets add-delegation --path a/b --succinct 32 bin",
            "",
            "Error: Not allowed to set delegated role options and the succinct option\n"
        )

        # Adding succinct hash delegation with zero bin amount.
        self._run(
            "edit targets add-delegation --succinct 0 bin",
            "",
            "Error: Succinct number must be at least 2\n"
        )

        # Adding succinct delegation with bin amount that is not a power of 2.
        self._run(
            "edit targets add-delegation --succinct 10 bin",
            "",
            "Error: Succinct number must be a power of 2\n"
        )

        # Running add-delegation without path, hash_prefix or succinct option
        self._run(
            "edit targets add-delegation delegate",
            "",
            "Error: Either paths/hash_prefix options must be set or succinct option\n"
        )

        # Trying to add a key for delegated bins in a target file without
        # succinct hash delegation.
        self._run(
            "edit targets add-key",
            "",
            "Error: No succinct delegations in ROLE\n"
        )

    def test_sign(self):
        """Test making changes without key, then signing with key"""
        subprocess.run(["git", "init", "."], cwd=self.cwd, capture_output=True)
        subprocess.run(["git", "config", "--local", "user.name", "test"], cwd=self.cwd)
        subprocess.run(["git", "config", "--local", "user.email", "test@example.com"], cwd=self.cwd)

        # Create initial metadata
        self._run("init")
        proc = self._run("verify", expected_out=None)
        subprocess.run(["git", "commit", "-a", "-m", "Initial metadata"], cwd=self.cwd, capture_output=True)

        files = {".git", "1.root.json", "1.snapshot.json", "1.targets.json", "private_keys", "timestamp.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

    	# bump root version without keys available
        os.rename(f"{self.cwd}/private_keys/keys.json", f"{self.cwd}/test_backup_keys.json")
        self._run("edit root touch")
        subprocess.run(["git", "commit", "-a", "-m", "Change without keys"], cwd=self.cwd, capture_output=True)
        os.rename(f"{self.cwd}/test_backup_keys.json", f"{self.cwd}/private_keys/keys.json")

        files |= {"2.root.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)
        proc = self._run("verify", expected_err="Error: Top-level metadata fails to validate: root was signed by 0/1 keys\n")

        # sign the change with keys available
        self._run("sign root")
        subprocess.run(["git", "commit", "-a", "-m", "Sign change"], cwd=self.cwd, capture_output=True)

        self.assertEqual(set(os.listdir(self.cwd)), files)
        proc = self._run("verify", expected_out=None)
        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")

        # bump targets version without keys available
        os.rename(f"{self.cwd}/private_keys/keys.json", f"{self.cwd}/test_backup_keys.json")
        self._run("edit targets touch")
        subprocess.run(["git", "commit", "-a", "-m", "Change without keys"], cwd=self.cwd, capture_output=True)
        os.rename(f"{self.cwd}/test_backup_keys.json", f"{self.cwd}/private_keys/keys.json")

        files |= {"2.targets.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)
        proc = self._run("verify", expected_out=None)

        # sign all targets with keys available
        self._run("sign --all-targets")
        subprocess.run(["git", "commit", "-a", "-m", "Sign change"], cwd=self.cwd, capture_output=True)

        self.assertEqual(set(os.listdir(self.cwd)), files)

        # Update snapshot to include new targets
        self._run("snapshot")

        files -= {"1.snapshot.json", "1.targets.json"}
        files |= {"2.snapshot.json"}
        self.assertEqual(set(os.listdir(self.cwd)), files)

        proc = self._run("verify", expected_out=None)
        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")

if __name__ == '__main__':
    unittest.main()
