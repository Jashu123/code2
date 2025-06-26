"""
This is a quick tool that reads over a test pool and checks that each column has acceptable values.

The test pool is specified in the command line arguments.
"""
import argparse
import csv
import difflib
import json
import logging
import re
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional, Tuple

__version__ = "1.0.0"


TIME_NOW = str(datetime.now())

POOL_CONFIG_JSON_FILE = Path(__file__).resolve().parent / "test_pool_verifier.json"
POOL_CONFIG = json.loads(POOL_CONFIG_JSON_FILE.read_text())

POOL_FILE_DEFAULT = Path(__file__).resolve().parent / "RedtailDP_MasterTestPool.csv"

VALID_DISABLED_OPTIONS = ["True", ""]

RE_JIRA_ID = r"[A-Z][A-Z0-9_]+-[1-9][0-9]*"
RE_MTP_NAME = r"([A-Za-z0-9-]+)(\d{4})_(\w+)"

OUTPUT_WIDTH = 75

EXTRA_VAL_KEY = "EXTRA_COLUMN_VAL"
NO_VAL_KEY = "NO_COLUMN_VAL"

FW_REPO_DEFAULT_DIR_NAME = "platform_fw"


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
    branch_out = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout
    if not branch_out:
        return "Unknown"
    return branch_out.read().strip().decode("utf-8")


def get_git_sha(path: Path):
    if not path.is_dir():
        raise TypeError("Expected path to be a dir. It was not.")

    command = "git rev-list --max-count=1 --skip=# HEAD".split()
    sha_out = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout
    if not sha_out:
        return "Unknown"
    return sha_out.read().strip().decode("utf-8")


class ProgressBar:
    def __init__(self, total: int, width: int = 50, desc: str = ""):
        self.total = total
        self.current = 0
        self.width = width
        self.desc = desc
        
    def update(self, current: int = None):
        if current is not None:
            self.current = current
        else:
            self.current += 1
            
        if self.total == 0:
            percentage = 100
        else:
            percentage = (self.current / self.total) * 100
            
        filled_width = int(self.width * self.current // self.total) if self.total > 0 else 0
        bar = '█' * filled_width + '-' * (self.width - filled_width)
        
        print(f'\r{self.desc}[{bar}] {self.current}/{self.total} ({percentage:.1f}%)', end='', flush=True)
        
        if self.current >= self.total:
            print()


def get_nearest_match(value: str, match_options: List[str]) -> List[str]:
    suggestions = difflib.get_close_matches(value, match_options, n=1, cutoff=0.1)
    if len(suggestions) > 0:
        return [suggestions[0]]

    return []


def print_pool_error(pool_file: Path, line_number: int, error_str: str, test_name: str = "") -> None:
    print()
    print(f"ERROR! {pool_file}:{line_number}")
    if test_name:
        print(f" - Test: {test_name}")
    print(f" - {error_str}")


def type_optional_int(item_str: str) -> Optional[int]:
    if not item_str:
        return None
    return int(item_str, 0)


def type_space_seperated_list(item_str: str) -> List[str]:
    if not isinstance(item_str, str):
        raise TypeError(
            f"cannot cast type {item_str.__name__} to a space sepereate list"
        )

    return item_str.split()


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
        self.disabled: str = kwargs["disabled"]
        self.notes: str = kwargs["notes"]
        self.stop_on_fail: str = kwargs["stop_on_fail"]
        self.name: str = kwargs["name"]
        self.path: Path = Path(kwargs["path"])
        self.base_arguments: List[str] = kwargs["base_arguments"]
        self.scalable_arguments: List[str] = kwargs["scalable_arguments"]
        self.environment: str = kwargs["environment"]
        self.domain: str = kwargs["domain"]
        self.category: str = kwargs["category"]
        self.features: List[str] = kwargs["features"]
        self.labels: List[str] = kwargs["labels"]
        self.author: str = kwargs["author"]
        self.build: List[str] = kwargs["build"]
        self.project: str = kwargs["project"]
        self.customer: str = kwargs["customer"]
        self.jira: str = kwargs["jira"]
        self.author: str = kwargs["author"]
        self.name: str = kwargs["name"]
        self.req_id: str = kwargs["req_id"]
        self.feature_id: str = kwargs["feature_id"]
        self.story_jira: str = kwargs["story_jira"]
        self.comment: str = kwargs["comment"]
        self.exclude_density: str = kwargs['exclude_density']
        self.alpha: str = kwargs["alpha"]
        self.pool: str = kwargs["pool"]
        self.loop_count: str = kwargs["loop_count"]
        self.redtail_only: str = kwargs["redtail_only"]
        self.deploy: str = kwargs["deploy"]
        self.new_script: str = kwargs["new_script"]
        self.pion: str = kwargs["pion"]
        self.hw_config: str = kwargs["hw_config"]
        self.special_hw: str = kwargs["special_hw"]
        self.dell_enablement_date: str = kwargs["dell_enablement_date"]
        self.hpe_enablement_date: str = kwargs["hpe_enablement_date"]
        self.reduction_date: str = kwargs["reduction_date"]
        self.test_duration: str = kwargs["test_duration"]
        self.platform: str = kwargs["platform"]
        self.script_level: str = kwargs["script_level"]
        self.nand_type: str = kwargs["b58r_b68s"]


        self.extra_args: Optional[List[str]] = kwargs.get(EXTRA_VAL_KEY)

        self.category_index: int = int(datetime.utcnow().timestamp())
        self.short_name: str = ""

    def check_values(self):
        check_not_extra_columns(self.extra_args)
        check_not_empty("Author", self.author)
        #check_valid_entries("Disabled", VALID_DISABLED_OPTIONS, self.disabled)
        check_valid_entries(
            "Environments", POOL_CONFIG["environments"], self.environment
        )
        check_valid_entries("Domains", POOL_CONFIG["domains"].keys(), self.domain)
        check_valid_entries(
            "Categories", POOL_CONFIG["categories"].keys(), self.category
        )
        check_valid_entries("Features", POOL_CONFIG["features"], self.features)
        check_valid_entries("Labels", POOL_CONFIG["labels"], self.labels)
        check_valid_entries("Build", POOL_CONFIG["builds"], self.build)
        check_valid_entries("Project", POOL_CONFIG["projects"], self.project)
        check_valid_entries("Customers", POOL_CONFIG["customers"], self.customer)
        # check_valid_jira(self.jira)

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
        self.add_column(
            "Scalable Arguments", type_space_seperated_list, "scalable_arguments"
        )
        self.add_column("Environment", str, "environment")
        self.add_column("Domain", str, "domain")
        self.add_column("Category", str, "category")
        self.add_column("Features", type_space_seperated_list, "features")
        self.add_column("Labels", type_space_seperated_list, "labels")
        self.add_column("Author", str, "author")
        self.add_column("Build", type_space_seperated_list, "build")
        self.add_column("Project", str, "project")
        self.add_column("Customer", str, "customer")
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
        self.add_column("New Script",str,"new_script")
        self.add_column("PION",str,"pion")
        self.add_column("HW_Config",str,"hw_config")
        self.add_column("Special_HW",str,"special_hw")
        self.add_column("DELL Enablement Date",str,"dell_enablement_date")
        self.add_column("HPE Enablement Date",str,"hpe_enablement_date")
        self.add_column("Reduction Date",str,"reduction_date")
        self.add_column("Test Duration",str,"test_duration")
        self.add_column("Platform",str,"platform")
        self.add_column("Script Level",str,"script_level")
        self.add_column("B58R_B68S", str, "b58r_b68s")

    def add_column(self, column_name: str, column_type: Callable, conversion_name: str):
        if not isinstance(column_name, str):
            raise InvalidColumn(f"Column name {column_name} must be a str.")

        self.columns_types[column_name] = (column_type, conversion_name)

    def convert_row(self, csv_row: dict) -> dict:
        convered_dict = {}

        for key, value in self.columns_types.items():
            column_type, conversion_name = value

            convered_dict[conversion_name] = column_type(csv_row[key])

        convered_dict[EXTRA_VAL_KEY] = csv_row.get(EXTRA_VAL_KEY)

        return convered_dict

    def parse_iter(self) -> Generator[Tuple[int, "FteTest"], None, None]:
        self.tests.clear()

        print(f"Parsing file {self.test_pool_path.name}")
        
        # First pass to count total rows for progress bar
        with self.test_pool_path.open("r", encoding="utf-8") as test_pool_reader:
            total_rows = sum(1 for _ in test_pool_reader) - 1
        
        progress_bar = ProgressBar(total_rows, desc="Validating: ")
        
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

                converted_row = self.convert_row(row)
                test = FteTest(**converted_row)
                self.tests.append(test)
                
                progress_bar.update(line_number - 1)
                
                yield line_number, test


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
        if short_category != POOL_CONFIG["categories"][test.category]:
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
        short_category = POOL_CONFIG["categories"][test.category]
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
            print_pool_error(parser.test_pool_path, test_index, str(failure), test.name)
            print(f"Suggested Name: {self.get_name_suggestions(test)}")


class CheckTestPath(TestRuleHandler):
    def __init__(self, args_dict: dict) -> None:
        self.fw_repo_path: Path = args_dict.get("fw_repo_path", Path())

    def __call__(self, test: FteTest, test_index: int) -> None:
        if self.fw_repo_path is None:
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
        if test.disabled == "True":
            return

        for argument in CheckArgumentPaths.PATH_ARGS_TO_CHECK:
            for index, base_arg in enumerate(test.base_arguments):
                self.check_arg_in_base_arg(test, index, argument, base_arg)


class CheckTestFunctionName(TestRuleHandler):
    def __init__(self, args_dict: dict) -> None:
        self.iris_enabled = args_dict.get("iris_enabled", False)

    def __call__(self, test: FteTest, test_index: int) -> None:
        if not self.iris_enabled:
            return
            
        if test.disabled == "True":
            return

        test_function_name = None
        for i, arg in enumerate(test.base_arguments):
            if arg.startswith("--test_function_name"):
                if "=" in arg:
                    test_function_name = arg.split("=", 1)[1]
                else:
                    if i + 1 < len(test.base_arguments):
                        test_function_name = test.base_arguments[i + 1]
                break

        if test_function_name is None:
            raise InvalidTestPoolEntry(
                f"Missing required argument --test_function_name in test {test.name}. "
                "All new test entries must include --test_function_name argument."
            )

        if test_function_name != test.name:
            raise InvalidTestPoolEntry(
                f"Argument --test_function_name value '{test_function_name}' does not match "
                f"Test Name column value '{test.name}'. These values must be identical."
            )


class VerifyReport:
    def __init__(self, args_dict: dict) -> None:
        self.test_passed = 0
        self.test_failed = 0

        test_pool = args_dict.get("test_pool", Path())
        self.test_exe_branch = get_git_branch(test_pool.parent)
        self.test_exe_sha = get_git_sha(test_pool.parent)

        fw_repo_path = args_dict.get("fw_repo_path", Path())
        fte_common_path = fw_repo_path / "test" / "fte_platform" / "fte_common"
        self.fte_common_branch = get_git_branch(fte_common_path)
        self.fte_common_sha = get_git_sha(fte_common_path)

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
                    args_dict.get("test_pool", Path()), line_number, str(ex), test.name
                )
            report.test_failed += 1
            print(f"Failed at row {line_number}, test: {test.name}")
            if not args_dict.get("continue_on_error") and not isinstance(
                ex, InvalidTestName
            ):
                print(f"\nStopping verification due to error at row {line_number}")
                exit(1)

    return report


def report_handlers(handlers: List[TestRuleHandler], parser: CsvParser):
    for handler in handlers:
        handler.report(parser)


def print_header():
    header_str = f"{Path(__file__).name} - {__version__} - {TIME_NOW}"
    print(f"{header_str:^{OUTPUT_WIDTH}}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="A tool to verify fte test pools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-p",
        "--test_pool",
        type=is_file,
        default=POOL_FILE_DEFAULT,
        help="The Path to the test pool to review",
    )
    parser.add_argument(
        "-fw",
        "--fw_repo_path",
        dest="fw_repo_path",
        type=is_dir,
        required=True,
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
    parser.add_argument(
        "--iris",
        dest="iris_enabled",
        action="store_true",
        default=False,
        help="Enable IRIS validation checks (test_function_name validation)",
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
  Basic validation:
    python test_pool_verifier.py -fw ~/src/platform_fw
  
  With IRIS enabled:
    python test_pool_verifier.py -fw ~/src/platform_fw --iris
  
  Continue on errors with IRIS:
    python test_pool_verifier.py -fw ~/src/platform_fw --iris -c
"""
    return parser.parse_args()


def main():
    print_header()
    args = parse_args()
    args_dict = vars(args)

    logging.basicConfig(level=args.loglevel)
    
    iris_status = "ENABLED" if args_dict.get("iris_enabled", False) else "DISABLED"
    print(f"IRIS Validation: {iris_status}")

    handlers = [
        CheckTestName(args_dict),
        CheckTestPath(args_dict),
        CheckArgumentPaths(args_dict),
        CheckTestFunctionName(args_dict),
    ]
    parser = CsvParser(args_dict.get("test_pool"))

    report = check_and_run_handlers(args_dict, handlers, parser)
    report_handlers(handlers, parser)
    print(f"\n{report}")
    if report.test_failed > 0:
        exit(1)


if __name__ == "__main__":
    main()
