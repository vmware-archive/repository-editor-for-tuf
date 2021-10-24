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

    def _run(self, args: str, expected_out:Optional[str]=None, expected_err:Optional[str]=None) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            args=["tufrepo"] + args.split(),
            capture_output=True, 
            cwd=self.cwd,
            text=True
        )
        if expected_out is not None:
           self.assertEqual(proc.stdout, expected_out)
        if expected_err is not None:
           self.assertEqual(proc.stderr, expected_err)
        self.assertEqual(proc.returncode, 0)

        return proc
 
    Data = NamedTuple("TestData", [("argv", List[str]), ("expect_out", str)])
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
        "add-target": Data("edit x add-target --help", "Usage: tufrepo edit ROLE add-target "),
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
        proc = self._run(data.argv, expected_err="")
        self.assertStartsWith(proc.stdout, data.expect_out)

    def test_repo_management(self):
        """Test (roughly) the tutorial from README"""
        subprocess.run(["git", "init", "."], cwd=self.cwd, capture_output=True)

        proc = self._run("edit root init", expected_err="", expected_out="")
        proc = self._run("edit root add-key root", expected_err="", expected_out="")
        proc = self._run("edit root add-key root", expected_err="", expected_out="")
        proc = self._run("edit root set-threshold root 2", expected_err="", expected_out="")
        proc = self._run("edit root add-key snapshot", expected_err="", expected_out="")
        proc = self._run("edit root add-key timestamp", expected_err="", expected_out="")
        proc = self._run("edit root add-key targets", expected_err="", expected_out="")
        files = ["1.root.json", ".git", "privkeys.json"]
        self.assertEqual(os.listdir(self.cwd), files)

        proc = self._run("edit timestamp init", expected_err="", expected_out="")
        proc = self._run("edit snapshot init", expected_err="", expected_out="")
        proc = self._run("edit targets init", expected_err="", expected_out="")
        files = ["1.root.json", "1.snapshot.json", ".git", "1.targets.json", "timestamp.json", "privkeys.json"]
        self.assertEqual(os.listdir(self.cwd), files)

        proc = self._run("snapshot", expected_err="", expected_out="")
        proc = self._run("verify", expected_err="")
        self.assertStartsWith(proc.stdout, "Metadata with 0 delegated targets verified")

        # TODO test all other commands

if __name__ == '__main__':
    unittest.main()