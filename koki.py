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
import shutil
import subprocess
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

__author__ = "Nicholas Baron"
__maintainer__ = "Nicholas Baron"
__version__ = "1.8.3"

TIME_NOW = str(datetime.now())

POOL_CONFIG_JSON_FILE = Path(__file__).resolve().parent / "test_pool_verifier.json"
POOL_CONFIG = json.loads(POOL_CONFIG_JSON_FILE.read_text())

POOL_FILE_DEFAULT = Path(__file__).resolve().parent / "Peregrine_MasterTestPool.csv"

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
        raise argparse.ArgumentTypeError("The given path {} is not a file.".format(path_str))
    return path


def is_dir(path_str):
    """Test if a string is a valid file path."""
    path = Path(path_str)
    if not path.is_dir():
        raise argparse.ArgumentTypeError("The given path {} is not a directory.".format(path_str))
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

    return ",".join(map(lambda p: "%s-%s" % tuple(p) if p[0] != p[1] else str(p[0]), ranges))


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

    command = "git rev-list --max-count=1 --skip=0 HEAD".split()
    sha_out = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout
    if not sha_out:
        return "Unknown"
    return sha_out.read().strip().decode("utf-8")


def get_nearest_match(value: str, match_options: List[str]) -> List[str]:
    suggestions = difflib.get_close_matches(value, match_options, n=1, cutoff=0.1)
    if len(suggestions) > 0:
        return [suggestions[0]]

    return []


def print_pool_error(pool_file: Path, line_number: int, error_str: str) -> None:
    print()
    print(f"ERROR! {pool_file}:{line_number}")
    print(f" - {error_str}")


def type_optional_int(item_str: str) -> Optional[int]:
    if not item_str:
        return None
    return int(item_str, 0)


def type_space_seperated_list(item_str: Any) -> List[str]:
    if not isinstance(item_str, str):
        raise TypeError(f"cannot cast type {type(item_str).__name__} to a space separated list")

    return item_str.split()


def type_args_from_string(arg_string: str) -> List[str]:
    arg_string = arg_string.strip()
    if not arg_string:
        return []
    
    raw_args = arg_string.split()

    args_list = []

    for item in raw_args:
        if item[0] == "-":
            args_list.append(item)
            continue

        if not args_list:
            raise InvalidTestPoolEntry(f"ERROR! bad arguments {arg_string}")

        args_list[-1] = args_list[-1] + "=" + item

    return args_list


def check_valid_jira(item_str: str) -> str:
    if not item_str:
        return item_str
    
    if re.fullmatch(RE_JIRA_ID, item_str) is None:
        raise InvalidTestPoolEntry(f"Found Jira Id {item_str} is not valid. Please ensure it is a valid Jira ID.")

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
            return given_entries

        for entry in given_entries:
            if entry and entry not in valid_entries:
                invalid_entries.append(entry)

    else:
        if given_entries and given_entries not in valid_entries:
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
        self.path: Path = Path(kwargs["path"])
        self.base_arguments: List[str] = kwargs["base_arguments"]
        self.scalable_arguments: List[str] = kwargs["scalable_arguments"]
        self.environment: str = kwargs["environment"]
        self.domain: str = kwargs["domain"]
        self.category: str = kwargs["category"]
        self.features: List[str] = kwargs["features"]
        self.labels: List[str] = kwargs["labels"]
        self.builds: List[str] = kwargs["builds"]
        self.project: str = kwargs["project"]
        self.customer: str = kwargs["customer"]
        self.jira: str = kwargs["jira"]
        self.author: str = kwargs["author"]
        self.name: str = kwargs["name"]
        self.req_id: str = kwargs["req_id"]
        self.feature_id: str = kwargs["feature_id"]
        self.exclude_density: str = kwargs["exclude_density"]
        self.pool: str = kwargs["pool"]
        self.hw_config: str = kwargs["hw_config"]
        self.script_level: str = kwargs["script_level"]
        self.special_hw: str = kwargs["special_hw"]

        self.extra_args: Optional[List[str]] = kwargs.get(EXTRA_VAL_KEY)

        self.category_index: int = int(datetime.utcnow().timestamp())
        self.short_name: str = ""

    def check_values(self):
        check_not_extra_columns(self.extra_args)
        check_not_empty("Author", self.author)
        check_valid_entries("Disabled", VALID_DISABLED_OPTIONS, self.disabled)
        if self.environment:
            check_valid_entries("Environments", POOL_CONFIG["environments"], self.environment)
        if self.domain:
            check_valid_entries("Domains", POOL_CONFIG["domains"].keys(), self.domain)
        if self.category:
            check_valid_entries("Categories", POOL_CONFIG["categories"].keys(), self.category)
        if self.features:
            check_valid_entries("Features", POOL_CONFIG["features"], self.features)
        if self.labels:
            check_valid_entries("Labels", POOL_CONFIG["labels"], self.labels)
        if self.builds:
            check_valid_entries("Builds", POOL_CONFIG["builds"], self.builds)
        if self.project:
            check_valid_entries("Project", POOL_CONFIG["projects"], self.project)
        if self.customer:
            check_valid_entries("Customers", POOL_CONFIG["customers"], self.customer)
        check_valid_jira(self.jira)

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
        self.add_column("Base Args", type_args_from_string, "base_arguments")
        self.add_column("Scalable Arguments", type_args_from_string, "scalable_arguments")
        self.add_column("Environment", str, "environment")
        self.add_column("Domain", str, "domain")
        self.add_column("Category", str, "category")
        self.add_column("Feature", type_space_seperated_list, "features")
        self.add_column("Labels", type_space_seperated_list, "labels")
        self.add_column("Author", str, "author")
        self.add_column("Build", type_space_seperated_list, "builds")
        self.add_column("Project", str, "project")
        self.add_column("Customer", type_space_seperated_list, "customer")
        self.add_column("EPIC JIRA", str, "jira")
        self.add_column("FeatureID", type_optional_int, "feature_id")
        self.add_column("ReqID", str, "req_id")
        self.add_column("Exclude Density", str, "exclude_density")
        self.add_column("Pool", str, "pool")
        self.add_column("HW_Config", str, "hw_config")
        self.add_column("Script Level", str, "script_level")
        self.add_column("Special_HW", str, "special_hw")

    def add_column(self, column_name: str, column_type: Callable, conversion_name: str):
        if not isinstance(column_name, str):
            raise InvalidColumn(f"Column name {column_name} must be a str.")

        self.columns_types[column_name] = (column_type, conversion_name)

    def convert_row(self, csv_row: dict) -> dict:
        convered_dict = {}

        if len(csv_row.items()) > len(self.columns_types):
            raise InvalidTestPoolEntry(f"There are too many columns in this row {len(csv_row.items())} > {len(self.columns_types)}")
        if len(csv_row.items()) < len(self.columns_types):
            raise InvalidTestPoolEntry(f"There are too few columns in this row {len(csv_row.items())} < {len(self.columns_types)}")

        for key, value in self.columns_types.items():
            column_type, conversion_name = value
            row_value = csv_row[key]
            try:
                convered_dict[conversion_name] = column_type(row_value)
            except Exception as ex:
                raise TypeError(
                    f'Failed to cast the column "{key}" to type {column_type.__name__} with value "{row_value}" because: {ex}'
                )

        convered_dict[EXTRA_VAL_KEY] = csv_row.get(EXTRA_VAL_KEY)

        return convered_dict

    def parse_iter(self, report: "VerifyReport") -> Generator[Tuple[int, "FteTest"], None, None]:
        self.tests.clear()

        print(f"Parsing file {self.test_pool_path.name}")
        with self.test_pool_path.open("r", encoding="ascii") as test_pool_reader:
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
                try:
                    converted_row = self.convert_row(row)
                    test = FteTest(**converted_row)
                    self.tests.append(test)
                    yield line_number, test
                except Exception as ex:
                    print_pool_error(self.test_pool_path, line_number, str(ex))
                    report.test_failed += 1


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
                "Please be sure there are letters numbers or dashes (-) representing the shortened category, followed by a 4 number index, then an underscore, finished by a user friendly name containing Alpha Numeric symbols and underscores (_)."
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
            raise InvalidTestNameIndex(f"Invalid test index {category_index}")

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

        print(f"Used index for {test.category}: {index_list_to_str(self.test_index_by_cat[test.category])}")
        category_index = 1
        while category_index in self.test_index_by_cat[test.category]:
            category_index += 1
        print(f"The Next Valid index is: {category_index}")

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
        if self.fw_repo_path is None:
            return

        if test.disabled == "True":
            return

        try:
            test_path_in_fw_repo = test.path.relative_to(FW_REPO_DEFAULT_DIR_NAME)
        except ValueError:
            raise InvalidTestPoolEntry(
                f'The test\'s path does not have the expected relative fw directory "{FW_REPO_DEFAULT_DIR_NAME}". '
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

    def verify_file_path(self, argument, test_path):
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

    def verify_path_in_base_arg(self, test, index, argument, base_arg):
        if base_arg.startswith(argument):
            if "=" in base_arg:
                potential_path_str = base_arg.split("=", maxsplit=1)[1]
            else:
                potential_path_str = test.base_arguments[index + 1]

            logging.info(f"Found that test {test.name} has path argument {argument} with path {potential_path_str}")

            potential_path_list = potential_path_str.split(",")
            for potential_path in potential_path_list:
                self.verify_file_path(argument, potential_path)

    def __call__(self, test: FteTest, test_index: int) -> None:
        if test.disabled == "True":
            return

        for argument in CheckArgumentPaths.PATH_ARGS_TO_CHECK:
            for index, base_arg in enumerate(test.base_arguments):
                self.verify_path_in_base_arg(test, index, argument, base_arg)


class CheckDuplicatedTests(TestRuleHandler):
    def __init__(self, args_dict: dict) -> None:
        self.test_tracking = {}
        self.duplicate_name = args_dict.get("duplicate_name")
        self.duplicate_args = None
        self.duplicate_pairs: List[Tuple[FteTest, FteTest, int, int]] = []

    def get_test_signature(self, test: FteTest) -> str:
        """Generate a unique signature for a test based on all columns except Test Name."""
        args_list = test.base_arguments.copy()
        args_list = list(set(args_list))
        args_list.sort()
        
        scalable_args_list = test.scalable_arguments.copy()
        scalable_args_list = list(set(scalable_args_list))
        scalable_args_list.sort()
        
        signature_components = [
            test.disabled,
            test.notes,
            test.stop_on_fail,
            str(test.path),
            ''.join(args_list),
            ''.join(scalable_args_list),
            test.environment,
            test.domain,
            test.category,
            ' '.join(sorted(test.features)),
            ' '.join(sorted(test.labels)),
            ' '.join(sorted(test.builds)),
            test.project,
            ' '.join(sorted(test.customer)),
            test.jira,
            test.author,
            test.req_id,
            str(test.feature_id),
            test.exclude_density,
            test.pool,
            test.hw_config,
            test.script_level,
            test.special_hw,
        ]
        
        return ''.join(signature_components)

    def __call__(self, test: FteTest, test_index: int) -> None:
        # Handle the original duplicate_name functionality
        if self.duplicate_name is not None:
            if self.duplicate_name == "all":
                args_list = test.base_arguments.copy()
                args_list = list(set(args_list))
                args_list.sort()
                sorted_filtered_args = f"{test.environment}{test.path}{''.join(args_list)}"
                
                old_test = self.test_tracking.get(sorted_filtered_args)
                if old_test is not None:
                    raise InvalidTestPoolEntry(
                        f"Duplicate test found! Current test {test.name} duplicates the test {old_test.get('test_name')} on line {old_test.get('line_num')}\n\t{sorted_filtered_args}"
                    )
                self.test_tracking[sorted_filtered_args] = {"test_name": test.name, "line_num": test_index}
            elif test.name == self.duplicate_name:
                print(f"INFO: Found test! {test.name}")
                args_list = test.base_arguments.copy()
                args_list = list(set(args_list))
                args_list.sort()
                self.duplicate_args = f"{test.environment}{test.path}{''.join(args_list)}"
                return
            else:
                args_list = test.base_arguments.copy()
                args_list = list(set(args_list))
                args_list.sort()
                sorted_filtered_args = f"{test.environment}{test.path}{''.join(args_list)}"
                self.test_tracking[sorted_filtered_args] = {"test_name": test.name, "line_num": test_index}
            return
        
        # Check for duplicate test combinations (all columns except Test Name)
        if test.disabled == "True":
            return
            
        test_signature = self.get_test_signature(test)
        
        existing_entry = self.test_tracking.get(test_signature)
        if existing_entry is not None:
            # Found a duplicate - store both tests and their line numbers
            self.duplicate_pairs.append((
                existing_entry['test'],
                test,
                existing_entry['line_num'],
                test_index
            ))
        else:
            self.test_tracking[test_signature] = {
                'test': test,
                'test_name': test.name,
                'line_num': test_index
            }

    def report(self, parser: "CsvParser"):
        # Handle original duplicate_name functionality
        if self.duplicate_name is not None:
            if self.duplicate_name == "all":
                return
            if self.duplicate_args is None:
                print(f"WARNING: The test \"{self.duplicate_name}\" was not found to check if it was duplicated.")
                return
            
            old_test = self.test_tracking.get(self.duplicate_args)
            if old_test is not None:
                print_pool_error(
                    parser.test_pool_path,
                    old_test.get("line_num"),
                    f"The test {self.duplicate_name} has a duplicate! {old_test.get('test_name')} on line {old_test.get('line_num')}",
                )
            return
        
        # Report duplicate combinations
        if not self.duplicate_pairs:
            print("\nNo duplicate test combinations found.")
            return
        
        print("\n" + "=" * OUTPUT_WIDTH)
        print(f"DUPLICATE TEST COMBINATIONS FOUND: {len(self.duplicate_pairs)} pairs")
        print("=" * OUTPUT_WIDTH)
        
        for idx, (original_test, duplicate_test, original_line, duplicate_line) in enumerate(self.duplicate_pairs, 1):
            print(f"\nDuplicate Pair #{idx}:")
            print(f"  Original:  Line {original_line:4d} - {original_test.name}")
            print(f"  Duplicate: Line {duplicate_line:4d} - {duplicate_test.name}")
            print(f"  Test Path: {original_test.path}")
            print(f"  Environment: {original_test.environment}")
            if original_test.base_arguments:
                args_preview = ' '.join(original_test.base_arguments[:3])
                if len(original_test.base_arguments) > 3:
                    args_preview += "..."
                print(f"  Base Args: {args_preview}")
        
        print("\n" + "=" * OUTPUT_WIDTH)
        
        # Ask user if they want to remove duplicates
        response = input(f"\nDo you want to remove all {len(self.duplicate_pairs)} duplicate tests and keep the originals? (yes/no): ").strip().lower()
        
        if response in ['yes', 'y']:
            self._remove_duplicates(parser)
        else:
            print("No changes made to the test pool.")

    def _remove_duplicates(self, parser: "CsvParser"):
        """Remove duplicate tests from the CSV file and create a backup."""
        try:
            # Create backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = parser.test_pool_path.parent / f"{parser.test_pool_path.stem}_backup_{timestamp}.csv"
            
            print(f"\nCreating backup: {backup_path}")
            shutil.copy2(parser.test_pool_path, backup_path)
            
            # Collect line numbers to delete (keep originals, remove duplicates)
            lines_to_delete = set()
            for _, _, _, duplicate_line in self.duplicate_pairs:
                lines_to_delete.add(duplicate_line)
            
            # Read the original file
            with parser.test_pool_path.open('r', encoding='ascii') as f:
                lines = f.readlines()
            
            # Write the cleaned file
            with parser.test_pool_path.open('w', encoding='ascii') as f:
                for line_num, line in enumerate(lines, start=1):
                    if line_num not in lines_to_delete:
                        f.write(line)
            
            print(f"\nSuccessfully removed {len(lines_to_delete)} duplicate tests.")
            print(f"Original file backed up to: {backup_path}")
            print(f"Updated file: {parser.test_pool_path}")
            
            # Print summary of removed tests
            print("\nRemoved tests:")
            removed_tests = [(test, line) for _, test, _, line in self.duplicate_pairs]
            removed_tests.sort(key=lambda x: x[1])
            for test, line_num in removed_tests:
                print(f"  Line {line_num:4d}: {test.name}")
                
        except Exception as e:
            print(f"\nERROR: Failed to remove duplicates: {e}")
            print("No changes were made to the original file.")


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


def check_and_run_handlers(args_dict: dict, handlers: List[TestRuleHandler], parser: CsvParser):
    report = VerifyReport(args_dict)

    for line_number, test in parser.parse_iter(report):
        try:
            test.check_values()

            for handler in handlers:
                handler(test, line_number)

            report.test_passed += 1
        except VerifierException as ex:
            if not isinstance(ex, InvalidTestName):
                print_pool_error(args_dict.get("test_pool", Path()), line_number, str(ex))
            report.test_failed += 1
            if not args_dict.get("continue_on_error") and not isinstance(ex, InvalidTestName):
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
        "-d",
        "--duplicate_name",
        dest="duplicate_name",
        type=str,
        default=None,
        help="Check for duplicate tests by test name ('all' for all duplicates)",
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
example:
python test_pool_verifier.py -fw ~/src/platform_fw
"""
    return parser.parse_args()


def main():
    print_header()
    args = parse_args()
    args_dict = vars(args)

    logging.basicConfig(level=args.loglevel)

    handlers = [
        CheckTestName(args_dict),
        CheckTestPath(args_dict),
        CheckArgumentPaths(args_dict),
        CheckDuplicatedTests(args_dict),
    ]
    parser = CsvParser(args_dict.get("test_pool"))

    report = check_and_run_handlers(args_dict, handlers, parser)
    report_handlers(handlers, parser)
    print(f"\n{report}")
    if report.test_failed > 0:
        exit(1)


if __name__ == "__main__":
    main()
