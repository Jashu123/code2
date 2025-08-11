#!/usr/bin/env python3
"""
This tool reads over a test pool, checks that each column has acceptable values,
and includes IRIS and VSSR compliance checking.

The test pool is specified in the command line arguments.
"""
import argparse
import csv
import difflib
import json
import logging
import re
import subprocess
import shutil
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional, Tuple

__author__ = "Nicholas Baron"
__maintainer__ = "jashu"
__version__ = "1.6.0"

TIME_NOW = str(datetime.now())

POOL_CONFIG_JSON_FILE = Path(__file__).resolve().parent / "test_pool_verifier.json"
try:
    POOL_CONFIG = json.loads(POOL_CONFIG_JSON_FILE.read_text())
except (FileNotFoundError, json.JSONDecodeError):
    POOL_CONFIG = {}

POOL_FILE_DEFAULT = Path(__file__).resolve().parent / "RedtailDP_MasterTestPool.csv"

VALID_DISABLED_OPTIONS = ["True", ""]

RE_JIRA_ID = r"[A-Z][A-Z0-9_]+-[1-9][0-9]*"
RE_MTP_NAME = r"([A-Za-z0-9-]+)(\d{4})_(\w+)"

OUTPUT_WIDTH = 75

EXTRA_VAL_KEY = "EXTRA_COLUMN_VAL"
NO_VAL_KEY = "NO_COLUMN_VAL"

FW_REPO_DEFAULT_DIR_NAME = "platform_fw"


# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @staticmethod
    def disable():
        """Disable colors for non-terminal output"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.RESET = ''


def colored_print(text: str, color: str = Colors.RESET, bold: bool = False):
    """Print colored text to terminal"""
    if not sys.stdout.isatty():
        Colors.disable()
    
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{text}{Colors.RESET}")


def print_progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', 
                      decimals: int = 1, length: int = 50, fill: str = '█', print_end: str = "\r"):
    """Print a progress bar to terminal"""
    if not sys.stdout.isatty():
        return  # Don't show progress bar in non-terminal output
        
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
    if iteration == total: 
        print()  # Print new line on completion


class VerifierException(Exception):
    pass


class InvalidTestArgument(VerifierException):
    pass


class InvalidTestPoolEntry(VerifierException):
    pass


class InvalidTestName(VerifierException):
    pass


class InvalidTestNameIndex(InvalidTestName):
    pass


class InvalidColumn(VerifierException):
    pass


def is_file(path_str):
    """Test if a string is a valid file path."""
    path = Path(path_str)
    if not path.is_file():
        raise argparse.ArgumentTypeError(
            "The given path {} is not a file.".format(path_str)
        )
    return path


def is_dir(path_str):
    """Test if a string is a valid file path."""
    path = Path(path_str)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(
            "The given path {} is not a directory.".format(path_str)
        )
    return path


def index_list_to_str(index_list):
    """A quick little hack to format a list of ints into a "1-4,6,10" style format.

    Args:
        index_list (List(int)): A list of ints.

    Returns:
        str: the string rendition of the list
    """
    if not index_list:
        return ""

    zones = list(set(index_list))
    zones.sort()

    range_id = 0
    ranges = [[zones[0], zones[0]]]
    for zone in list(zones):
        if ranges[range_id][1] in (zone, zone - 1):
            ranges[range_id][1] = zone
        else:
            ranges.append([zone, zone])
            range_id += 1

    return ",".join(
        map(lambda p: "%s-%s" % tuple(p) if p[0] != p[1] else str(p[0]), ranges)
    )


def get_git_branch(path: Path):
    if not path.is_dir():
        raise TypeError("Expected path to be a dir. It was not.")

    command = "git rev-parse --abbrev-ref HEAD".split()
    try:
        branch_out = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout
        if not branch_out:
            return "Unknown"
        return branch_out.read().strip().decode("utf-8")
    except:
        return "Unknown"


def get_git_sha(path: Path):
    if not path.is_dir():
        raise TypeError("Expected path to be a dir. It was not.")

    command = "git rev-list --max-count=1 --skip=# HEAD".split()
    try:
        sha_out = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout
        if not sha_out:
            return "Unknown"
        return sha_out.read().strip().decode("utf-8")
    except:
        return "Unknown"


def get_nearest_match(value: str, match_options: List[str]) -> List[str]:
    suggestions = difflib.get_close_matches(value, match_options, n=1, cutoff=0.1)
    if len(suggestions) > 0:
        return [suggestions[0]]

    return []


def print_pool_error(pool_file: Path, line_number: int, error_str: str) -> None:
    print()
    colored_print(f"ERROR! {pool_file}:{line_number}", Colors.RED, bold=True)
    colored_print(f" - {error_str}", Colors.RED)


def type_optional_int(item_str: str) -> Optional[int]:
    if not item_str:
        return None
    return int(item_str, 0)


def type_space_seperated_list(item_str: str) -> List[str]:
    if not isinstance(item_str, str):
        raise TypeError(
            f"cannot cast type {item_str.__name__} to a space sepereate list"
        )

    return item_str.split() if item_str.strip() else []


def check_valid_jira(item_str: str) -> str:
    if re.fullmatch(RE_JIRA_ID, item_str) is None:
        raise InvalidTestPoolEntry(
            f"Found Jira Id {item_str} is not valid. Please ensure it is a valid Jira ID."
        )

    return item_str


def check_not_empty(entry_name: str, given_entry) -> str:
    if not given_entry:
        raise InvalidTestPoolEntry(f"{entry_name} is blank! It must contain something.")

    return given_entry


def check_not_extra_columns(extra_columns: Optional[List]) -> Optional[List]:
    if extra_columns:
        raise InvalidColumn(
            f" There are too many columns in this row. Extra column values: {extra_columns}\n"
            + "Please check that the columns are aligned, use proper parenthesis where needed."
        )

    return extra_columns


def check_valid_entries(column_name: str, valid_entries: List[str], given_entries):
    if not POOL_CONFIG:  # Skip validation if config doesn't exist
        return given_entries
        
    invalid_entries = []

    if isinstance(given_entries, list):

        if not given_entries:
            raise InvalidTestPoolEntry(
                f"The column {column_name} is empty! We expect at least one of {valid_entries}"
            )

        for entry in given_entries:
            if entry not in valid_entries:
                invalid_entries.append(entry)

    else:
        if given_entries not in valid_entries:
            invalid_entries.append(given_entries)

    if invalid_entries:
        entry_error = [
            f'Column: "{column_name}" Entries: {invalid_entries} are not valid.',
            f"Please choose from the list below or reference {POOL_CONFIG_JSON_FILE} if you would like to add an option.",
            f"{valid_entries}",
        ]

        all_suggestions: List[str] = []

        for entry in invalid_entries:
            all_suggestions.extend(get_nearest_match(entry, valid_entries))

        if len(all_suggestions) > 0:
            entry_error[0] += f" Did you mean? {all_suggestions}"

        raise InvalidTestPoolEntry("\n".join(entry_error))

    return given_entries


class FteTest:
    def __init__(self, **kwargs) -> None:
        self.disabled: str = kwargs.get("disabled", "")
        self.notes: str = kwargs.get("notes", "")
        self.stop_on_fail: str = kwargs.get("stop_on_fail", "")
        self.name: str = kwargs.get("name", "")
        self.path: Path = Path(kwargs.get("path", ""))
        self.base_arguments: List[str] = kwargs.get("base_arguments", [])
        self.scalable_arguments: List[str] = kwargs.get("scalable_arguments", [])
        self.environment: str = kwargs.get("environment", "")
        self.domain: str = kwargs.get("domain", "")
        self.category: str = kwargs.get("category", "")
        self.features: List[str] = kwargs.get("features", [])
        self.labels: List[str] = kwargs.get("labels", [])
        self.author: str = kwargs.get("author", "")
        self.build: List[str] = kwargs.get("build", [])
        self.project: str = kwargs.get("project", "")
        self.customer: List[str] = kwargs.get("customer", [])
        self.jira: str = kwargs.get("jira", "")
        self.req_id: str = kwargs.get("req_id", "")
        self.feature_id: str = kwargs.get("feature_id", "")
        self.story_jira: str = kwargs.get("story_jira", "")
        self.comment: str = kwargs.get("comment", "")
        self.exclude_density: str = kwargs.get('exclude_density', "")
        self.alpha: str = kwargs.get("alpha", "")
        self.pool: str = kwargs.get("pool", "")
        self.loop_count: str = kwargs.get("loop_count", "")
        self.redtail_only: str = kwargs.get("redtail_only", "")
        self.deploy: str = kwargs.get("deploy", "")
        self.new_script: str = kwargs.get("new_script", "")
        self.pion: str = kwargs.get("pion", "")
        self.hw_config: str = kwargs.get("hw_config", "")
        self.special_hw: str = kwargs.get("special_hw", "")
        self.dell_enablement_date: str = kwargs.get("dell_enablement_date", "")
        self.hpe_enablement_date: str = kwargs.get("hpe_enablement_date", "")
        self.reduction_date: str = kwargs.get("reduction_date", "")
        self.test_duration: str = kwargs.get("test_duration", "")
        self.platform: str = kwargs.get("platform", "")
        self.script_level: str = kwargs.get("script_level", "")
        self.tag: str = kwargs.get("tag", "")

        self.extra_args: Optional[List[str]] = kwargs.get(EXTRA_VAL_KEY)

        self.category_index: int = int(datetime.utcnow().timestamp())
        self.short_name: str = ""

    def check_values(self):
        if not POOL_CONFIG:  # Skip validation if config doesn't exist
            return
            
        check_not_extra_columns(self.extra_args)
        check_not_empty("Author", self.author)
        #check_valid_entries("Disabled", VALID_DISABLED_OPTIONS, self.disabled)
        check_valid_entries(
            "Environments", POOL_CONFIG.get("environments", []), self.environment
        )
        check_valid_entries("Domains", POOL_CONFIG.get("domains", {}).keys(), self.domain)
        check_valid_entries(
            "Categories", POOL_CONFIG.get("categories", {}).keys(), self.category
        )
        check_valid_entries("Features", POOL_CONFIG.get("features", []), self.features)
        check_valid_entries("Labels", POOL_CONFIG.get("labels", []), self.labels)
        check_valid_entries("Build", POOL_CONFIG.get("builds", []), self.build)
        check_valid_entries("Project", POOL_CONFIG.get("projects", []), self.project)
        check_valid_entries("Customers", POOL_CONFIG.get("customers", []), self.customer)
        # check_valid_jira(self.jira)

    def has_argument(self, arg_flag: str) -> bool:
        """Check if base_arguments contains the specified argument flag."""
        for arg in self.base_arguments:
            # Check for exact match or flag with equals sign
            if arg == arg_flag or arg.startswith(arg_flag + '='):
                return True
        return False

    def get_test_function_name_value(self) -> str:
        """Extract the value of --test_function_name from base_arguments."""
        for arg in self.base_arguments:
            if arg.startswith('--test_function_name='):
                return arg.split('=', 1)[1]
        return ""

    def check_iris_compliance(self) -> List[str]:
        """Check IRIS compliance and return list of issues."""
        issues = []
        
        # Check if --test_function_name is present
        if not self.has_argument('--test_function_name'):
            issues.append("Missing --test_function_name argument")
        else:
            # Check if the value matches the Test Name
            function_name_value = self.get_test_function_name_value()
            if function_name_value != self.name:
                issues.append(f"--test_function_name='{function_name_value}' does not match Test Name '{self.name}'")
        
        return issues

    def check_vssr_compliance(self) -> List[str]:
        """Check VSSR compliance and return list of issues."""
        issues = []
        
        # Pools that require --vssr_enable
        vssr_pools = ["Feature", "LeveragedTests", "SMBUS", "VDM"]
        # Pools that require --stress_test
        stress_pools = ["IOStress", "ResetsIO", "APLCPD", "B2BAPL", "RandomEI"]
        
        if self.pool in vssr_pools:
            if not self.has_argument('--vssr_enable'):
                issues.append(f"Pool={self.pool} but missing --vssr_enable argument")
        elif self.pool in stress_pools:
            if not self.has_argument('--stress_test'):
                issues.append(f"Pool={self.pool} but missing --stress_test argument")
        
        return issues

    def __str__(self):
        return self.name


class CsvParser:
    def __init__(self, test_pool_path: Path):
        self.test_pool_path = test_pool_path
        self.columns_types: OrderedDict[str, Tuple[Callable, str]] = OrderedDict()
        self.tests: List[FteTest] = []

        self.add_column("Disable", str, "disabled")
        self.add_column("Notes", str, "notes")
        self.add_column("Stop On Fail", str, "stop_on_fail")
        self.add_column("Test Name", str, "name")
        self.add_column("Test Path", str, "path")
        self.add_column("Base Args", type_space_seperated_list, "base_arguments")
        self.add_column("Scalable Arguments", type_space_seperated_list, "scalable_arguments")
        self.add_column("Environment", str, "environment")
        self.add_column("Domain", str, "domain")
        self.add_column("Category", str, "category")
        self.add_column("Feature", type_space_seperated_list, "features")
        self.add_column("Labels", type_space_seperated_list, "labels")
        self.add_column("Author", str, "author")
        self.add_column("Build", type_space_seperated_list, "build")
        self.add_column("Project", str, "project")
        self.add_column("Customer", type_space_seperated_list, "customer")
        self.add_column("EPIC JIRA", str, "jira")
        self.add_column("FeatureID", type_optional_int, "feature_id")
        self.add_column("ReqID", str, "req_id")
        self.add_column("STORY JIRA", str, "story_jira")
        self.add_column("Comment", str, "comment")
        self.add_column("Exclude Density", str, "exclude_density")
        self.add_column("Alpha", str, "alpha")
        self.add_column("Pool", str, "pool")
        self.add_column("LoopCount", str, "loop_count")
        self.add_column("RedtailOnly", str, "redtail_only")
        self.add_column("Deploy", str, "deploy")
        self.add_column("New Script", str, "new_script")
        self.add_column("PION", str, "pion")
        self.add_column("HW_Config", str, "hw_config")
        self.add_column("Special_HW", str, "special_hw")
        self.add_column("DELL Enablement Date", str, "dell_enablement_date")
        self.add_column("HPE Enablement Date", str, "hpe_enablement_date")
        self.add_column("Reduction Date", str, "reduction_date")
        self.add_column("Test Duration", str, "test_duration")
        self.add_column("Platform", str, "platform")
        self.add_column("Script Level", str, "script_level")
        self.add_column("Tag", str, "tag")

    def add_column(self, column_name: str, column_type: Callable, conversion_name: str):
        if not isinstance(column_name, str):
            raise InvalidColumn(f"Column name {column_name} must be a str.")

        self.columns_types[column_name] = (column_type, conversion_name)

    def convert_row(self, csv_row: dict) -> dict:
        convered_dict = {}

        for key, value in self.columns_types.items():
            column_type, conversion_name = value
            raw_value = csv_row.get(key, "")
            
            try:
                convered_dict[conversion_name] = column_type(raw_value)
            except (ValueError, TypeError) as e:
                logging.warning(f"Error converting {key}='{raw_value}': {e}")
                convered_dict[conversion_name] = raw_value if column_type == str else column_type("")

        convered_dict[EXTRA_VAL_KEY] = csv_row.get(EXTRA_VAL_KEY)

        return convered_dict

    def parse_iter(self) -> Generator[Tuple[int, "FteTest"], None, None]:
        self.tests.clear()

        colored_print(f"Parsing file {self.test_pool_path.name}", Colors.CYAN, bold=True)
        
        # First pass to count total lines for progress bar
        with self.test_pool_path.open("r", encoding="utf-8") as test_pool_reader:
            total_lines = sum(1 for _ in test_pool_reader) - 1  # Subtract header
        
        with self.test_pool_path.open("r", encoding="utf-8") as test_pool_reader:
            test_pool_dict_reader = csv.DictReader(
                test_pool_reader,
                list(self.columns_types.keys()),
                restkey=EXTRA_VAL_KEY,
                restval=NO_VAL_KEY,
            )

            for line_number, row in enumerate(test_pool_dict_reader, start=1):
                logging.info(f" - Parsing {line_number} : {row.values()}")
                if line_number == 1:
                    continue

                # Show progress bar
                if total_lines > 0:
                    print_progress_bar(line_number - 1, total_lines, 
                                     prefix='Progress:', suffix='Complete', length=40)

                converted_row = self.convert_row(row)
                test = FteTest(**converted_row)
                self.tests.append(test)
                yield line_number, test
        
        # Ensure progress bar shows 100% completion
        if total_lines > 0:
            print_progress_bar(total_lines, total_lines, 
                             prefix='Progress:', suffix='Complete', length=40)


class TestRuleHandler:
    def __init__(self, args_dict: dict) -> None:
        pass

    def __call__(self, test: FteTest, test_index: int) -> None:
        pass

    def __str__(self) -> str:
        return self.__class__.__name__

    def report(self, parser: "CsvParser"):
        pass


class CheckTestName(TestRuleHandler):
    def __init__(self, args_dict: dict):
        self.skip_name_check = args_dict.get("skip_name_check")

        self.test_index_by_cat: Dict[str, List[int]] = {}
        self.all_test_names: List[str] = []

        self.name_failures: List[Tuple] = []

    def get_name_parts(self, test: FteTest) -> Tuple:
        re_match = re.fullmatch(RE_MTP_NAME, test.name)

        if not re_match:
            raise InvalidTestName(
                f"Invalid Test name {test.name} must match with the regex {RE_MTP_NAME}\n"
                "Please be sure there are letters followed by 4 numbers, an underscore, followed by a user friendly name."
            )

        short_category, category_index, short_name = re_match.groups()

        return (short_category, int(category_index), short_name)

    def check_category(self, test: FteTest, short_category):
        if not POOL_CONFIG or "categories" not in POOL_CONFIG:
            return
            
        if short_category != POOL_CONFIG["categories"].get(test.category):
            raise InvalidTestName(
                f"Invalid short form category in {test.name} it should be {POOL_CONFIG['categories'][test.category]}"
            )

    def check_index(self, test: FteTest, category_index: int):
        if self.test_index_by_cat.get(test.category) is None:
            self.test_index_by_cat[test.category] = []

        if category_index not in self.test_index_by_cat[test.category]:
            self.test_index_by_cat[test.category].append(category_index)
        else:
            raise InvalidTestName(f"Invalid test index {category_index}")

    def check_unique_name(self, test: FteTest):
        raise_error = False
        if test.name in self.all_test_names:
            raise_error = True

        self.all_test_names.append(test.name)

        if raise_error:
            raise InvalidTestName(
                f"Test name is not unique! {test.name}. Duplicated on line {self.all_test_names.index(test.name)+2}."
            )

    def get_name_suggestions(self, test: FteTest):
        if not POOL_CONFIG or "categories" not in POOL_CONFIG:
            short_category = "XXXX"
        else:
            short_category = POOL_CONFIG["categories"].get(test.category, "XXXX")
            
        user_friendly_name = test.path.stem

        if self.test_index_by_cat.get(test.category) is None:
            self.test_index_by_cat[test.category] = []

        print(
            f"Used index for {test.category}: {index_list_to_str(self.test_index_by_cat[test.category])}"
        )
        category_index = 1
        while category_index in self.test_index_by_cat[test.category]:
            category_index += 1

        self.test_index_by_cat[test.category].append(category_index)

        return f"{short_category}{category_index:04d}_{user_friendly_name}"

    def __call__(self, test: FteTest, test_index: int) -> None:
        if self.skip_name_check:
            return

        try:
            short_category, category_index, short_name = self.get_name_parts(test)
            self.check_unique_name(test)
            self.check_category(test, short_category)
            self.check_index(test, category_index)
        except InvalidTestName as ex:
            self.name_failures.append((test, ex, test_index))
            raise

    def report(self, parser: "CsvParser"):

        if not self.name_failures:
            return

        for test, failure, test_index in self.name_failures:
            print_pool_error(parser.test_pool_path, test_index, str(failure))
            print(f"Suggested Name: {self.get_name_suggestions(test)}")


class CheckTestPath(TestRuleHandler):
    def __init__(self, args_dict: dict) -> None:
        self.fw_repo_path: Path = args_dict.get("fw_repo_path", Path())

    def __call__(self, test: FteTest, test_index: int) -> None:
        if self.fw_repo_path is None or not self.fw_repo_path.exists():
            return

        if test.disabled == "True":
            return

        try:
            test_path_in_fw_repo = test.path.relative_to(FW_REPO_DEFAULT_DIR_NAME)
        except ValueError:
            raise InvalidTestPoolEntry(
                f'The test\'s path does not have the expecteds relative fw directory "{FW_REPO_DEFAULT_DIR_NAME}". '
                'Please be sure the path is in the form: \n"platform_fw/test/fte_platform/fte_common/common_integration'
                '/test_scripts/blackbox/number_of_writes_and_reads.py"'
            )

        full_repo_path = self.fw_repo_path / test_path_in_fw_repo
        if full_repo_path.exists() and full_repo_path.is_file():
            return

        raise InvalidTestPoolEntry(
            f'Could not find the test path "{test.path}"\nChecked the full path {full_repo_path}\n'
            "Please be sure that platform_fw, fte_common are at tip. "
            "And that test_execution:tip is merged into your branch."
        )


class CheckArgumentPaths(TestRuleHandler):

    PATH_ARGS_TO_CHECK = [
        "-W",
        "--test_config",
        "--runner_config",
        "--subsystem_config",
    ]

    def __init__(self, args_dict: dict) -> None:
        fw_repo_path: Path = args_dict.get("fw_repo_path", Path())
        self.fte_repo_path: Path = fw_repo_path / "test" / "fte_platform" / "fte_common"

    def check_arg_in_base_arg(self, test, index, argument, base_arg):
        if argument in base_arg:

            if "=" in base_arg:
                test_path = base_arg.split("=", maxsplit=1)[1]
            else:
                test_path = test.base_arguments[index + 1]

            logging.info(
                f"Found that test {test.name} has path argument {argument} with path {test_path}"
            )

            if "fte_common" in test_path:
                raise InvalidTestArgument(
                    f"The argument {argument} has been "
                    "flagged to be a path relative to fte_common. "
                    "Please check to be sure that the path in this "
                    'argument does not contain "test/fte_platform/'
                    f'fte_common"\nBad Path: {test_path}'
                )

            full_path = self.fte_repo_path / test_path
            if full_path.exists() and full_path.is_file():
                return

            raise InvalidTestPoolEntry(
                f'Could not find the argument {argument} path "{test_path}"\nChecked the full path {full_path}\n'
                "Please check that the file exists."
            )

    def __call__(self, test: FteTest, test_index: int) -> None:
        if not self.fte_repo_path.exists():
            return
            
        if test.disabled == "True":
            return

        for argument in CheckArgumentPaths.PATH_ARGS_TO_CHECK:
            for index, base_arg in enumerate(test.base_arguments):
                self.check_arg_in_base_arg(test, index, argument, base_arg)


class VerifyReport:
    def __init__(self, args_dict: dict) -> None:
        self.test_passed = 0
        self.test_failed = 0

        test_pool = args_dict.get("test_pool", Path())
        if test_pool and test_pool.parent.exists():
            self.test_exe_branch = get_git_branch(test_pool.parent)
            self.test_exe_sha = get_git_sha(test_pool.parent)
        else:
            self.test_exe_branch = "Unknown"
            self.test_exe_sha = "Unknown"

        fw_repo_path = args_dict.get("fw_repo_path", Path())
        if fw_repo_path and fw_repo_path.exists():
            fte_common_path = fw_repo_path / "test" / "fte_platform" / "fte_common"
            if fte_common_path.exists():
                self.fte_common_branch = get_git_branch(fte_common_path)
                self.fte_common_sha = get_git_sha(fte_common_path)
            else:
                self.fte_common_branch = "Unknown"
                self.fte_common_sha = "Unknown"
        else:
            self.fte_common_branch = "Unknown"
            self.fte_common_sha = "Unknown"

        self.file = test_pool

    @property
    def test_total(self) -> int:
        return self.test_passed + self.test_failed

    @property
    def result(self) -> str:
        if not self.test_total:
            return "NOT STARTED"
        return "PASSED" if self.test_failed == 0 else "FAILED"

    def __str__(self):

        # Header
        ret_str = f"{' Pool Verify Report ':#^{OUTPUT_WIDTH}}\n"

        # File Info
        ret_str += f"{'Date: ':<8}{TIME_NOW:<{OUTPUT_WIDTH-8}}\n"
        ret_str += f"{'Test Exe Branch: ':<8}{self.test_exe_branch:<{OUTPUT_WIDTH-8}}\n"
        ret_str += f"{'Test Exe Sha: ':<8}{str(self.test_exe_sha):<{OUTPUT_WIDTH-8}}\n"
        ret_str += f"{'ETF Branch: ':<8}{self.fte_common_branch:<{OUTPUT_WIDTH-8}}\n"
        ret_str += f"{'ETF Sha: ':<8}{str(self.fte_common_sha):<{OUTPUT_WIDTH-8}}\n"
        ret_str += f"{'File: ':<8}{str(self.file.name):<{OUTPUT_WIDTH-8}}\n"

        # Results
        passed_str = f"Passed: {self.test_passed}"
        failed_str = f"Failed: {self.test_failed}"
        total_str = f"Total: {self.test_total}"
        ret_str += f"{passed_str:<{OUTPUT_WIDTH//3}}"
        ret_str += f"{failed_str:^{OUTPUT_WIDTH//3}}"
        ret_str += f"{total_str:>{OUTPUT_WIDTH//3}}\n"

        # Footer
        result_str = f" FINAL RESULT: {self.result} "
        ret_str += f"{result_str:#^{OUTPUT_WIDTH}}"
        return ret_str


def check_and_run_handlers(
    args_dict: dict, handlers: List[TestRuleHandler], parser: CsvParser
):
    report = VerifyReport(args_dict)

    for line_number, test in parser.parse_iter():
        try:
            test.check_values()

            for handler in handlers:
                handler(test, line_number)

            report.test_passed += 1
        except VerifierException as ex:
            if not isinstance(ex, InvalidTestName):
                print_pool_error(
                    args_dict.get("test_pool", Path()), line_number, str(ex)
                )
            report.test_failed += 1
            if not args_dict.get("continue_on_error") and not isinstance(
                ex, InvalidTestName
            ):
                exit(1)

    return report


def report_handlers(handlers: List[TestRuleHandler], parser: CsvParser):
    for handler in handlers:
        handler.report(parser)


def print_header():
    header_str = f"{Path(__file__).name} - {__version__} - {TIME_NOW}"
    colored_print(f"{header_str:^{OUTPUT_WIDTH}}", Colors.CYAN, bold=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="A tool to verify and modify fte test pools. Includes IRIS and VSSR compliance checking.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-fw",
        "--fw_repo_path",
        dest="fw_repo_path",
        type=is_dir,
        help="The Path to the FW repo for test path checking",
    )
    parser.add_argument(
        "-c",
        "--continue_on_error",
        dest="continue_on_error",
        action="store_true",
        help="Continue testing the pool on error",
    )
    parser.add_argument(
        "-n",
        "--skip_name_check",
        dest="skip_name_check",
        action="store_true",
        help="Skip validation of test names",
    )
    
    # Validation options
    parser.add_argument(
        "--iris_check",
        action="store_true",
        help="Report all entries missing --test_function_name or where it doesn't match Test Name"
    )
    parser.add_argument(
        "--vssr_check", 
        action="store_true",
        help="Check Pool=Feature,LeveragedTests,SMBUS,VDM for --vssr_enable and Pool=IOStress,ResetsIO,APLCPD,B2BAPL,RandomEI for --stress_test"
    )
    parser.add_argument(
        "--full_check",
        action="store_true", 
        help="Run both IRIS and VSSR compliance checks"
    )
    
    parser.add_argument(
        "--debug",
        help="Print lots of debugging statements",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        "--verbose",
        help="Be verbose",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )
    parser.epilog = """
examples:
# Original validation mode
python test_pool_verifier.py -fw ~/src/platform_fw

# IRIS compliance check - reports missing or mismatched --test_function_name
python test_pool_verifier.py --iris_check

# VSSR compliance check - reports missing --vssr_enable or --stress_test for specific pools
python test_pool_verifier.py --vssr_check

# Full compliance check - runs both IRIS and VSSR checks
python test_pool_verifier.py --full_check
"""
    return parser.parse_args()


def main():
    print_header()
    args = parse_args()
    args_dict = vars(args)

    logging.basicConfig(level=args.loglevel)

    parser = CsvParser(POOL_FILE_DEFAULT)

    # Handle full check mode (both IRIS and VSSR)
    if args.full_check:
        colored_print("Running FULL compliance check (IRIS + VSSR)...", Colors.MAGENTA, bold=True)
        colored_print("=" * 60, Colors.MAGENTA)
        
        # Load all tests
        for line_number, test in parser.parse_iter():
            pass
        
        total_iris_issues = 0
        total_vssr_issues = 0
        tests_with_iris_issues = 0
        tests_with_vssr_issues = 0
        relevant_vssr_tests = 0
        
        colored_print("\n[INFO] IRIS COMPLIANCE CHECK", Colors.BLUE, bold=True)
        colored_print("-" * 30, Colors.BLUE)
        
        for test in parser.tests:
            iris_issues = test.check_iris_compliance()
            if iris_issues:
                if tests_with_iris_issues == 0:
                    print()
                tests_with_iris_issues += 1
                colored_print(f"Test: {test.name}", Colors.YELLOW, bold=True)
                for issue in iris_issues:
                    colored_print(f"  [X] {issue}", Colors.RED)
                    total_iris_issues += 1
                print()
        
        if total_iris_issues == 0:
            colored_print("[PASS] All tests are IRIS compliant!", Colors.GREEN, bold=True)
        else:
            colored_print(f"[FAIL] Found {total_iris_issues} IRIS issue(s) across {tests_with_iris_issues} test(s)", Colors.RED, bold=True)
        
        colored_print("\n[INFO] VSSR COMPLIANCE CHECK", Colors.BLUE, bold=True)
        colored_print("-" * 30, Colors.BLUE)
        
        for test in parser.tests:
            if test.pool in ["Feature", "LeveragedTests", "SMBUS", "VDM", "IOStress", "ResetsIO", "APLCPD", "B2BAPL", "RandomEI"]:
                relevant_vssr_tests += 1
                vssr_issues = test.check_vssr_compliance()
                if vssr_issues:
                    if tests_with_vssr_issues == 0:
                        print()
                    tests_with_vssr_issues += 1
                    colored_print(f"Test: {test.name}", Colors.YELLOW, bold=True)
                    colored_print(f"  Pool: {test.pool}", Colors.CYAN)
                    for issue in vssr_issues:
                        colored_print(f"  [X] {issue}", Colors.RED)
                        total_vssr_issues += 1
                    print()
        
        if total_vssr_issues == 0:
            colored_print(f"[PASS] All {relevant_vssr_tests} relevant tests are VSSR compliant!", Colors.GREEN, bold=True)
        else:
            colored_print(f"[FAIL] Found {total_vssr_issues} VSSR issue(s) across {tests_with_vssr_issues} test(s)", Colors.RED, bold=True)
        
        colored_print("\n[SUMMARY]", Colors.MAGENTA, bold=True)
        colored_print("-" * 20, Colors.MAGENTA)
        print(f"Total tests checked: {len(parser.tests)}")
        print(f"IRIS issues: {total_iris_issues}")
        print(f"VSSR issues: {total_vssr_issues}")
        status = "[PASS]" if (total_iris_issues + total_vssr_issues) == 0 else "[FAIL]"
        status_color = Colors.GREEN if (total_iris_issues + total_vssr_issues) == 0 else Colors.RED
        colored_print(f"Overall status: {status}", status_color, bold=True)
        
        # Check if compliance checks failed - if so, skip original validation
        if total_iris_issues > 0 or total_vssr_issues > 0:
            colored_print("\n[WARNING] SKIPPING ORIGINAL VALIDATION", Colors.YELLOW, bold=True)
            colored_print("Compliance checks failed. Please fix the above issues before running full validation.", Colors.YELLOW)
            exit(1)
        
        # Continue to original validation only if compliance checks passed
        colored_print("\n[PASS] All compliance checks passed! Proceeding with original validation...", Colors.GREEN, bold=True)

    # Handle IRIS check mode
    elif args.iris_check:
        colored_print("Running IRIS compliance check...", Colors.BLUE, bold=True)
        colored_print("=" * 60, Colors.BLUE)
        
        # Load all tests
        for line_number, test in parser.parse_iter():
            pass
        
        total_issues = 0
        tests_with_issues = 0
        for test in parser.tests:
            issues = test.check_iris_compliance()
            if issues:
                if tests_with_issues == 0:  # Only print header once
                    print()
                tests_with_issues += 1
                colored_print(f"Test: {test.name}", Colors.YELLOW, bold=True)
                for issue in issues:
                    colored_print(f"  [X] {issue}", Colors.RED)
                    total_issues += 1
                print()
        
        if total_issues == 0:
            colored_print("\n[PASS] All tests are IRIS compliant!", Colors.GREEN, bold=True)
        else:
            colored_print(f"[FAIL] Found {total_issues} IRIS compliance issue(s) across {tests_with_issues} test(s)", Colors.RED, bold=True)
        
        # Check if IRIS compliance failed - if so, skip original validation
        if total_issues > 0:
            colored_print("\n[WARNING] SKIPPING ORIGINAL VALIDATION", Colors.YELLOW, bold=True)
            colored_print("IRIS compliance check failed. Please fix the above issues before running full validation.", Colors.YELLOW)
            exit(1)
        
        # Continue to original validation only if IRIS compliance passed
        colored_print("\n[PASS] IRIS compliance check passed! Proceeding with original validation...", Colors.GREEN, bold=True)

    # Handle VSSR check mode
    elif args.vssr_check:
        colored_print("Running VSSR compliance check...", Colors.BLUE, bold=True)
        colored_print("=" * 60, Colors.BLUE)
        
        # Load all tests
        for line_number, test in parser.parse_iter():
            pass
        
        total_issues = 0
        relevant_tests = 0
        tests_with_issues = 0
        
        for test in parser.tests:
            if test.pool in ["Feature", "IOStress"]:
                relevant_tests += 1
                issues = test.check_vssr_compliance()
                if issues:
                    if tests_with_issues == 0:  # Only print header once
                        print()
                    tests_with_issues += 1
                    colored_print(f"Test: {test.name}", Colors.YELLOW, bold=True)
                    colored_print(f"  Pool: {test.pool}", Colors.CYAN)
                    for issue in issues:
                        colored_print(f"  ❌ {issue}", Colors.RED)
                        total_issues += 1
                    print()
        
        if total_issues == 0:
            colored_print(f"\n[PASS] All {relevant_tests} relevant tests are VSSR compliant!", Colors.GREEN, bold=True)
        else:
            colored_print(f"[FAIL] Found {total_issues} VSSR compliance issue(s) across {tests_with_issues} test(s)", Colors.RED, bold=True)
        
        # Check if VSSR compliance failed - if so, skip original validation
        if total_issues > 0:
            colored_print("\n[WARNING] SKIPPING ORIGINAL VALIDATION", Colors.YELLOW, bold=True)
            colored_print("VSSR compliance check failed. Please fix the above issues before running full validation.", Colors.YELLOW)
            exit(1)
        
        # Continue to original validation only if VSSR compliance passed
        colored_print("\n[PASS] VSSR compliance check passed! Proceeding with original validation...", Colors.GREEN, bold=True)

    # Original validation mode
    colored_print(f"\n{'='*60}", Colors.CYAN)
    colored_print("Running original validation...", Colors.CYAN, bold=True)
    colored_print("=" * 60, Colors.CYAN)
    
    if not args.fw_repo_path:
        colored_print("WARNING: -fw/--fw_repo_path not provided, skipping path validation", Colors.YELLOW, bold=True)
        handlers = [CheckTestName(args_dict)]
    else:
        handlers = [
            CheckTestName(args_dict),
            CheckTestPath(args_dict),
            CheckArgumentPaths(args_dict),
        ]

    # If tests weren't already loaded by compliance checks, load them now
    if not hasattr(parser, 'tests') or not parser.tests:
        for line_number, test in parser.parse_iter():
            pass

    # Run original validation on already loaded tests
    report = VerifyReport(args_dict)
    
    for test in parser.tests:
        line_number = parser.tests.index(test) + 2  # +2 for header and 1-based indexing
        try:
            test.check_values()

            for handler in handlers:
                handler(test, line_number)

            report.test_passed += 1
        except VerifierException as ex:
            if not isinstance(ex, InvalidTestName):
                print_pool_error(
                    args_dict.get("test_pool", Path()), line_number, str(ex)
                )
            report.test_failed += 1
            if not args_dict.get("continue_on_error") and not isinstance(
                ex, InvalidTestName
            ):
                exit(1)

    # Report handlers
    for handler in handlers:
        handler.report(parser)
        
    print(f"\n{report}")
    if report.test_failed > 0:
        exit(1)


if __name__ == "__main__":
    main()
