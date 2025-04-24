
import argparse
import json
import logging
import os
import signal
import threading
import time
from collections import Counter
from concurrent.futures import Future, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from io import TextIOWrapper
from multiprocessing import Manager
from multiprocessing.managers import SyncManager
from pathlib import Path
from threading import Event
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

__author__ = "Nicholas Baron"
__maintainer__ = "Nicholas Baron"
__version__ = "2.0.3"

TIME_NOW = str(datetime.now())
COMMAND_HEADER = f"[{Path(__file__).name} - {__version__} - {TIME_NOW}]"

BYTE_PER_MEGABYTE = 1024 * 1024

PARSE_STATUS_INTERVAL = 5

REPORT_MAX_ERROR_COUNT = 15
REPORT_TABLE_ROW_COUNT = 5
REPORT_MAX_TRACEBACK_LINES = 10


CONFIG: Dict[str, Any] = {
    "log_health": {
        "crc_error_rate": {"healthy": 0.1, "usable": 80},
        "parse_error_rate": {"healthy": 0.1, "usable": 10},
    },
    "section_health": {
        "crc_error_rate": {"healthy": 0.1},
    },
    "strings_to_count": [
        "Allow IO on Namespaces",
        "BTAG_STATUS: 0x00000009",
        "Cap Test Failed",
        "command timeout",
        "eFIFO - Command error",
        "eFIFO - PSFA and HDPA error status",
        "empty page",
        "Empty Page",
        "Error PCIe Link Issue - Link Recovery failure detected",
        "exception",
        "HCRC_ERROR",
        "HDPA Error",
        "hif command timeout",
        "in-flight commands",
        "IO command Error'ed completion sent",
        "IO command error",
        "PCIE_CURR_GEN_SPEED: 0x01",
        "program fail",
        "Program Fail",
        "READ_ERROR_RAIN_RECOVERY_ERROR",
        "READ_ERROR_RAIN_RECOVERY_SUCCESS",
        "timeout",
        "WP Manager: Setting EOL Reason",
        "WP_REASON",
        "Write Protect",
    ],
}

SUPPORTED_ELOG_HEADERS = {
    "power_cycle_count": 0,
    "power_cycle_time_ns": 1,
    "power_cycle_time_formatted": 2,
    "_source": 3,
    "log_level": 4,
    "cpu_name": 5,
    "domain": 6,
    "component": 7,
    "subcomponent": 8,
    "module": 9,
    "line_number": 10,
    "message": 11,
    "parameters": 12,
    "lifetime_seconds": 13,
    "event_id": 14,
    "gid": 15,
    "free_text": 16,
    "blob": 17,
    "wallclock_time": 18,
}

PANIC_STATUS_MESSAGES = {
    0x50000000: "STATUS_CS_PANIC_FROM_INITIALIZATION_REENTRANCY",
    0x50000001: "STATUS_CS_PANIC_FROM_ASSERT",
    0x50000002: "STATUS_CS_PANIC_FROM_UNHANDLED_EXCEPTION",
    0x50000003: "STATUS_CS_PANIC_FROM_UNHANDLED_INTERRUPT",
    0x50000004: "STATUS_CS_PANIC_FROM_ANOTHER_CPU",
    0x50000005: "STATUS_CS_PANIC_FROM_HW_WATCHDOG",
    0x50000006: "STATUS_CS_PANIC_FROM_BOOT_FAILURE",
    0x50000007: "STATUS_CS_CONFIG_INVALID_SKU_ID",
    0x50000008: "STATUS_CS_CONFIG_INVALID_CUSTOMER_ID",
    0x50000009: "STATUS_CS_UNABLE_TO_RESTORE_PANIC_CAUSE",
    0x5000000A: "STATUS_CS_PANIC_FROM_UNCORR_DRAM",
    0x5000000B: "STATUS_CS_PANIC_FROM_UNCORR_SRAM",
    0x5000000C: "STATUS_CS_PANIC_FROM_HARDWARE_ERROR",
    0x5000000D: "STATUS_CS_SNAPSHOT",
    0x5000000E: "STATUS_CS_DEBUGSTOP",
}


def setup_logger(verbose=False):
    log_level = logging.DEBUG if verbose else logging.INFO
    formatting = (
        "[%(asctime)s] pid: %(process)d %(levelname)s %(funcName)s - %(message)s"
        if verbose
        else "[%(asctime)s] pid: %(process)d - %(message)s"
    )
    logging.basicConfig(
        format=formatting,
        level=log_level,
    )
    logger.info(f"Logging with level {logging.getLevelName(log_level)}")


def type_job_count(job_str):
    """Check to see if requested jobs are valid"""
    if job_str.lower() == "all":
        requested_jobs = os.cpu_count() or 1
    else:
        requested_jobs = int(job_str, 0)
    cpu_count = os.cpu_count() or 1

    if requested_jobs > cpu_count:
        raise argparse.ArgumentTypeError(
            "The given job count cannot be more than the CPU count of the processor {}>{}".format(
                requested_jobs, os.cpu_count()
            )
        )
    return requested_jobs


def type_is_file(path_str):
    """Check to see if a string is a valid file path"""
    path = Path(path_str)
    if not path.is_file():
        raise argparse.ArgumentTypeError("The given path {} is not a file.".format(path_str))
    return path


def type_is_dir(path_str):
    """Check to see if a string is a valid dir path"""
    path = Path(path_str)
    if not path.is_dir():
        raise argparse.ArgumentTypeError("The given path {} is not a directory.".format(path_str))
    return path


def percentage(part, whole):
    return 100 * float(part) / float(whole)


def read_reverse_order(file_name: Path):
    with open(file_name, "rb") as reader:
        reader.seek(0, os.SEEK_END)
        pointer_location = reader.tell()
        buffer = bytearray()
        while pointer_location >= 0:
            reader.seek(pointer_location)
            pointer_location = pointer_location - 1
            new_byte = reader.read(1)
            if new_byte == b"\n":
                yield buffer.decode(errors="replace")[::-1]
                buffer = bytearray()
            else:
                buffer.extend(new_byte)

        if len(buffer) > 0:
            yield buffer.decode()[::-1]


def get_line_item(line: List[str], column: str) -> str:
    return line[SUPPORTED_ELOG_HEADERS[column]]


def parse_parameters(parameters_str: str) -> dict:
    ret_dict: Dict[str, Union[str, int]] = {}
    parameters_str = parameters_str.replace(" ", "")

    for item in parameters_str.split(";"):
        if not item:
            continue
        split_item = item.strip().split(":", maxsplit=1)
        key = split_item[0]
        value = split_item[-1]
        try:
            ret_dict[key.strip()] = int(value.strip(), 0)
        except ValueError:
            ret_dict[key.strip()] = value.strip()
    return ret_dict


def check_headers(csv_file: Path) -> Tuple["EventLogHealth", str]:
    with csv_file.open("r", errors="replace") as reader:
        file_headers = reader.readline().strip().split(",")

        for header, expected_header in zip(file_headers, SUPPORTED_ELOG_HEADERS.keys()):
            if header != expected_header:
                return (
                    EventLogHealth.Unparsable,
                    f"expected CSV headers dont match {header=} {expected_header=}, {Path(__file__).name} may be incompatible with this event log",
                )
    return EventLogHealth.Healthy, "healthy"


class OutputWriter:
    def __init__(self, writer: TextIOWrapper) -> None:
        self._writer: TextIOWrapper = writer
        self._errors: List[str] = []
        self._sections: List[str] = []
        self._metrics: List[str] = []

    def add(self, error: Optional[str], section: Optional[str], non_human_metric: Optional[str]):
        if error:
            self._errors.append(error)
        if section:
            self._sections.append(section)
        if non_human_metric:
            self._metrics.append(non_human_metric)

    def write_line(self, string: str):
        string = string.strip() + "\n"
        self._writer.write(string)

    def commit(self):
        if self._errors:
            self.write_line(self._errors[0])
        for section in self._sections:
            self.write_line(section)
            self.write_line("----")
        for metric in self._metrics:
            self.write_line(metric)
            self.write_line("----")


@dataclass(repr=True)
class EventLogNameInfo:
    coyote_sn: str = field(default="unknown")
    coyote_port: str = field(default="unknown")
    start_time: Optional[datetime] = field(default=None)
    stop_time: Optional[datetime] = field(default=None)
    index: Optional[int] = field(default=None)

    def __str__(self):
        return f"coyote sn: {self.coyote_sn} coyote_port: {self.coyote_port} start_time: {self.start_time} stop_time: {self.stop_time} file_index: {self.index}"

    @classmethod
    def from_file(cls, csv_file: Path) -> Tuple["EventLogNameInfo", "EventLogHealth", str]:
        file_name: str = csv_file.name
        return_class = cls()
        health = EventLogHealth.Healthy
        health_reason = "healthy"
        try:
            file_parts = file_name.split("-")

            return_class.coyote_sn = file_parts[1]
            return_class.coyote_port = file_parts[2]

            return_class.start_time = datetime.strptime(" ".join(file_parts[3:5]), "%Y%m%d_%H%M%S %f")
            return_class.stop_time = datetime.strptime(" ".join(file_parts[5:7]), "%Y%m%d_%H%M%S %f")

            return_class.index = int(file_parts[7].replace(".bin.csv", ""))
        except Exception:
            health = EventLogHealth.Unparsable
            health_reason = f"event log name ({csv_file.name}) does not match the expected format"
        return return_class, health, health_reason


class EventLogStats:
    def __init__(self, **kwargs) -> None:
        self._raw = kwargs.copy()

        logger.debug(f"self._raw: {json.dumps(self._raw, indent=4)}")

        self.files_parsed = kwargs.pop("files_parsed", 1)

        self.num_packets = int(kwargs.pop("Num_packets", 0))
        self.crc_errors = int(kwargs.pop("CRC_Errors", 0))
        self.message_gaps = int(kwargs.pop("Message_gaps", 0))
        self.message_gap_lost_packets = int(kwargs.pop("Message_gap_lost_packets", 0))
        self.message_wraps = int(kwargs.pop("Message_wraps", 0))
        self.discarded_partial_messages = int(kwargs.pop("Discarded_Partial_Messages", 0))
        self.parse_errors = int(kwargs.pop("Parse_Errors", 0))
        self.unique_fwid = int(kwargs.pop("Unique_FWID", 0))
        self.total_fwid = int(kwargs.pop("Total_FWID", 0))
        self.bin_raw_size_bytes = int(kwargs.pop("bin_raw_size_bytes", 0))
        self.total_event_count = int(kwargs.pop("total_event_count", 0))
        self.assert_count = int(kwargs.pop("assert_count", 0))
        self.hw_error_count = int(kwargs.pop("hw_error_count", 0))
        self.serial_number = str(kwargs.pop("serial_number", ""))
        self.log_power_cycles = int(kwargs.pop("log_power_cycles", 0))
        self.hw_timestamp_rollback_count = int(kwargs.pop("hw_timestamp_rollback_count", 0))
        self.hw_timestamp_nonboot_rollback = int(kwargs.pop("hw_timestamp_nonboot_rollback", 0))
        self.hw_overflow_count = int(kwargs.pop("hw_overflow_count", 0))
        self.power_cycle_count_decremented = int(kwargs.pop("power_cycle_count_decremented", 0))
        self.lifetime_sec_decremented = int(kwargs.pop("lifetime_sec_decremented", 0))
        self.lifetime_sec_max_delta = int(kwargs.pop("lifetime_sec_max_delta", 0))
        self.fwid_list = str(kwargs.pop("FWID_list", ""))
        self.warn_count = int(kwargs.pop("WARN_count", 0))
        self.err_count = int(kwargs.pop("ERR_count", 0))
        self.crit_count = int(kwargs.pop("CRIT_count", 0))
        self.blob_dword_mismatch = int(kwargs.pop("blob_dword_mismatch", 0))
        self.crc_error_pct = float(kwargs.pop("CRC_Error_pct", 0))
        self.stuck_bits = int(kwargs.pop("Stuck_Bits", 0))
        self.bad_crc_segments = int(kwargs.pop("Bad CRC Segments", 0))
        self.skipped_16k_chunks = int(kwargs.pop("Skipped_16k_chunks", 0))

        self.log_decoder_version = kwargs.pop("Version", "unknown")
        self.log_decoder_command = kwargs.pop("decode_command", "unknown")
        self.elapsed_file_time = kwargs.pop("ElapsedFiletime", "unknown")

        self.log_metric_list = kwargs.pop("raw_lines", "unknown")

        if self.num_packets > 0:
            self.crc_error_rate = percentage(self.crc_errors, self.num_packets)
            self.parse_error_rate = percentage(self.parse_errors, self.num_packets)
        else:
            self.crc_error_rate = -1
            self.parse_error_rate = -1

    @property
    def log_metric(self):
        return "\n".join(self.log_metric_list[::-1])

    @property
    def test_infra_metric(self):
        return {
            "Num_packets": self.num_packets,
            "CRC_Errors": self.crc_errors,
            "Message_gaps": self.message_gaps,
            "Message_gap_lost_packets": self.message_gap_lost_packets,
            "Message_wraps": self.message_wraps,
            "Discarded_Partial_Messages": self.discarded_partial_messages,
            "Parse_Errors": self.parse_errors,
            "Unique_FWID": self.unique_fwid,
            "Total_FWID": self.total_fwid,
            "bin_raw_size_bytes": self.bin_raw_size_bytes,
            "total_event_count": self.total_event_count,
            "assert_count": self.assert_count,
            "CRC_Error_rate": f"Rate: {self.crc_error_rate:.01f}%",
        }

    @classmethod
    def from_file(cls, csv_file: Path) -> Tuple["EventLogStats", "EventLogHealth", str]:
        stats_health = EventLogHealth.Healthy
        stats_health_reason = "healthy"
        found_lines = 0

        params: Dict[str, Any] = {"files_parsed": 1, "raw_lines": []}
        for index, line in enumerate(read_reverse_order(csv_file)):
            if not line:
                continue

            line_split = line.split(",")

            if (get_line_item(line_split, "subcomponent") == "app_info") and (
                get_line_item(line_split, "message") == "Log Info"
            ):
                params.update(parse_parameters(get_line_item(line_split, "parameters")))
                params.update(parse_parameters(get_line_item(line_split, "free_text")))
                params["raw_lines"].append(line)
                found_lines += 1

            if (get_line_item(line_split, "subcomponent") == "app_info") and (
                get_line_item(line_split, "message") == "Decoder Info"
            ):
                params.update(parse_parameters(get_line_item(line_split, "parameters")))
                params.update({"decode_command": get_line_item(line_split, "free_text")})
                params["raw_lines"].append(line)
                found_lines += 1

            if found_lines == 2:
                logger.debug(f"Found all Log Info Lines for {csv_file.name}")
                break

            if index > 5:
                stats_health = EventLogHealth.Unparsable
                stats_health_reason = f"Could not find the Log Info in the last {index} lines of the file"
                break

        return cls(**params), stats_health, stats_health_reason

    def __add__(self, cls):
        if not isinstance(cls, EventLogStats):
            raise NotImplementedError(f"cannot add {cls.__class__.__name__} to {self.__class__.__name__}")

        new_dict = {}
        all_keys = set(self._raw.keys())
        all_keys.update(cls._raw.keys())

        for key in all_keys:
            lhs_value = self._raw.get(key)
            rhs_value = cls._raw.get(key)

            if lhs_value is None:
                new_dict[key] = rhs_value
                continue
            if rhs_value is None:
                new_dict[key] = lhs_value
                continue

            if isinstance(lhs_value, str):
                new_dict[key] = lhs_value
            elif isinstance(rhs_value, str):
                new_dict[key] = rhs_value
            elif isinstance(lhs_value, (int, float)) and isinstance(rhs_value, (int, float)):
                new_dict[key] = lhs_value + rhs_value
            elif isinstance(rhs_value, list):
                new_dict[key] = rhs_value
            else:
                raise NotImplementedError(f"Unable to handle value type {key=} {type(lhs_value)=} {type(rhs_value)=}")

        return EventLogStats(**new_dict)

    def __str__(self):
        relevant_info = [
            f"Crc Err: {self.crc_error_rate:.2f}%",
            f"Parse Err: {self.parse_error_rate:.2f}%",
            f"Stuck Bits: {self.stuck_bits}",
            f"Msg Gaps: {self.message_gaps}",
            f"Total Events: {self.total_event_count}",
            f"Files Parsed: {self.files_parsed}",
        ]
        return "  ".join(relevant_info)


class EventLogHealth(Enum):
    Healthy = auto()
    Usable = auto()
    Bad = auto()
    Unparsable = auto()

    @classmethod
    def from_stats(cls, csv_stats: EventLogStats) -> Tuple["EventLogHealth", str]:
        return_class = cls.Healthy
        reason = "healthy"

        if csv_stats.parse_error_rate > CONFIG["log_health"]["parse_error_rate"]["healthy"]:
            return_class = cls.Usable
            reason = f"parse error rate ({csv_stats.parse_error_rate:.02f}%) > minimum allowed healthy rate ({CONFIG['log_health']['parse_error_rate']['healthy']:.02f}%)"
            logger.debug(reason)
        if csv_stats.crc_error_rate > CONFIG["log_health"]["crc_error_rate"]["healthy"]:
            return_class = cls.Usable
            reason = f"crc error rate ({csv_stats.crc_error_rate:.02f}%) > minimum allowed healthy rate ({CONFIG['log_health']['crc_error_rate']['healthy']:.02f}%)"
            logger.debug(reason)
        if csv_stats.parse_error_rate > CONFIG["log_health"]["parse_error_rate"]["usable"]:
            return_class = cls.Bad
            reason = f"parse error rate ({csv_stats.parse_error_rate:.02f}%) > minimum allowed usable rate ({CONFIG['log_health']['parse_error_rate']['usable']:.02f}%)"
            logger.debug(reason)
        if csv_stats.crc_error_rate > CONFIG["log_health"]["crc_error_rate"]["usable"]:
            return_class = cls.Bad
            reason = f"crc error rate ({csv_stats.crc_error_rate:.02f}%) > minimum allowed usable rate ({CONFIG['log_health']['crc_error_rate']['usable']:.02f}%)"
            logger.debug(reason)

        return return_class, reason


class MessageManager:
    def __init__(self) -> None:
        self.data: List["Message"] = []

    def add(self, messages: List["Message"]):
        self.data.extend(messages)

    def debug_dump(self, output_writer: OutputWriter, verbose: bool = False):
        if not verbose:
            return
        for data in self.data:
            output_writer.write_line(str(data))

    def reverse_filter(self, filters: List["AbstractStatefulFilter"]):
        for message in reversed(self.data):
            for filter in filters:
                filter.filter_message_from_reversed_list(message)

    def forward_parse(self, filters: List["AbstractStatefulFilter"]):
        for message in self.data:
            for filter in filters:
                filter.parse_message_from_forward_list(message)

    def errors(self, error_limit=25):
        return_str = ""
        printed_errors = 0
        for item in self.data:
            if not isinstance(item.subclass, Error):
                continue

            if item.deleted:
                continue

            return_str += f"{item.subclass.message(item)}"
            printed_errors += 1

            if printed_errors > error_limit:
                break

        return return_str


class EventLogFile:
    def __init__(self, file_path: Path) -> None:
        self.path = file_path
        self.info, info_health, info_health_reason = EventLogNameInfo.from_file(self.path)
        header_health, header_health_reason = check_headers(self.path)
        self.stats, stats_health, stats_health_reason = EventLogStats.from_file(self.path)

        self.health = EventLogHealth.Healthy
        self.health_reason = "healthy"

        init_health_list = [info_health, header_health, stats_health]
        init_health_reason_list = [info_health_reason, header_health_reason, stats_health_reason]

        for health, reason in zip(init_health_list, init_health_reason_list):
            if health != EventLogHealth.Healthy:
                self.health = health
                self.health_reason = reason
                return

        self.health, self.health_reason = EventLogHealth.from_stats(self.stats)

    def _read_status_iterator(self, log_reader: TextIOWrapper):
        file_size = self.path.stat().st_size
        total_read = 0
        last_read = 0

        start_time = time.time()
        current_time = start_time
        prev_status_message_time = start_time
        duration_since_last_status = 1.0

        logger.info(
            f"{self.path.name} - {current_time - start_time:.01f}s - {((total_read - last_read) // BYTE_PER_MEGABYTE) // duration_since_last_status} MB/sec - {total_read // BYTE_PER_MEGABYTE}/{file_size // BYTE_PER_MEGABYTE}MB - {total_read / file_size:.1%}"
        )

        for line_num, line in enumerate(log_reader):
            total_read += len(line.encode("utf-8"))
            current_time = time.time()

            duration_since_last_status = current_time - prev_status_message_time
            if duration_since_last_status > PARSE_STATUS_INTERVAL:
                logger.info(
                    f"{self.path.name} - {current_time - start_time:.01f}s - {((total_read - last_read) // BYTE_PER_MEGABYTE) // duration_since_last_status} MB/sec - {total_read // BYTE_PER_MEGABYTE}/{file_size // BYTE_PER_MEGABYTE}MB - {total_read / file_size:.1%}"
                )
                prev_status_message_time = current_time
                last_read = total_read

            yield line_num, line

        else:
            logger.info(
                f"{self.path.name} - {current_time - start_time:.01f}s - {((total_read - last_read) // BYTE_PER_MEGABYTE) // duration_since_last_status} MB/sec - {total_read // BYTE_PER_MEGABYTE}/{file_size // BYTE_PER_MEGABYTE}MB - {total_read / file_size:.1%}"
            )

    def _execute_filters_per_line(self, filters: List["AbstractStatefulFilter"], return_messages: List["Message"]):
        bad_col_line_count = 0

        with self.path.open("r", errors="replace") as log_reader:
            for line_num, line in self._read_status_iterator(log_reader):
                try:
                    split_line = line.split(",")

                    if len(split_line) < len(SUPPORTED_ELOG_HEADERS.keys()):
                        bad_col_line_count += 1
                        continue

                    for reporter in filters:
                        results = reporter.parse_event(self.path, line_num, line, split_line)
                        if results:
                            return_messages.extend(results)
                except Exception as ex:
                    logger.debug(f"Failed to parse line {line_num}: {line}\n{ex}")
                    raise

        return bad_col_line_count

    def parse(self, event: Event, filters: List["AbstractStatefulFilter"]):
        if event.is_set():
            return []

        logger.info(f"Started parsing event log {self.path.name}")

        return_messages = [
            Message(
                self.path,
                -1,
                self.__class__.__name__,
                Statistic(StatisticType.LogInfo, self.info),
            ),
            Message(
                self.path,
                -1,
                self.__class__.__name__,
                Statistic(StatisticType.LogStats, self.stats),
            ),
        ]

        if self.health == EventLogHealth.Bad or self.health == EventLogHealth.Unparsable:
            logger.error(f"{self.path.name} has health {self.health} {self.health_reason}. Will not parse.")
            return_messages.extend(
                [
                    Message(
                        self.path,
                        -1,
                        self.__class__.__name__,
                        Statistic(StatisticType.LogHealth, (self.health, self.health_reason)),
                    ),
                    Message(self.path, -1, self.__class__.__name__, Action.StopDeleteSegment),
                ]
            )
            return return_messages

        try:
            logger.info(f"{self.path.name} has health {self.health} {self.health_reason}. Parsing.")
            bad_col_line_count = self._execute_filters_per_line(filters, return_messages)
            return_messages.append(
                Message(
                    self.path,
                    -1,
                    self.__class__.__name__,
                    Statistic(StatisticType.BadColumnLineCount, bad_col_line_count),
                )
            )
        except KeyboardInterrupt:
            logger.warning(f"Canceling parsing event log {self.path.name}")
            event.set()
            self.health = EventLogHealth.Unparsable
            self.health_reason = "Parsing canceled by keyboard"
        except Exception as ex:
            logger.exception(f"Failed parsing file {self.path.name} {ex}")
            self.health = EventLogHealth.Unparsable
            self.health_reason = f"Exception while parsing: {str(ex)[-50:]}"
        else:
            logger.info(f"Finished parsing event log {self.path.name}")

        return_messages.append(
            Message(
                self.path,
                -1,
                self.__class__.__name__,
                Statistic(StatisticType.LogHealth, (self.health, self.health_reason)),
            )
        )
        return return_messages


class AbstractStatefulFilter:
    def __init__(self) -> None: ...

    @property
    def classname(self):
        return self.__class__.__name__

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        """This function should never modify this class. It will remain stateless. So it can be used in multiprocessing."""
        ...

    def filter_message_from_reversed_list(self, message) -> Any:
        """This function can modify this class for tracking the filter state."""
        ...

    def parse_message_from_forward_list(self, message) -> Any:
        """This function will likely modify this class for tracking and reporting metrics."""
        ...

    def report(self, report_table: "ReportTable") -> Optional[str]: ...


@dataclass(repr=True)
class Message:
    file: Path
    line_num: int
    origin: str
    subclass: Any
    deleted: bool = False


@dataclass(repr=True)
class Error:
    core_name: str
    sub_component: str
    line: List[str]

    def message(self, message: Message):
        return f"{self.core_name} {self.sub_component.upper()}! {message.file.name}:{message.line_num} \n" + ",".join(
            self.line
        )


class StatisticType(Enum):
    BadColumnLineCount = auto()
    CoresDumped = auto()
    CountedString = auto()
    DecoderHint = auto()
    LogHealth = auto()
    LogInfo = auto()
    LogStats = auto()
    PanicCoreLeader = auto()
    PanicedCore = auto()
    SegmentCrc = auto()
    TimedOutHtag = auto()
    TimedOutOpcode = auto()


@dataclass(repr=True)
class Statistic:
    type: StatisticType
    value: Any


class Action(Enum):
    StartDeleteSegment = auto()
    StopDeleteSegment = auto()


class LogHealthReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.total_health: List[Tuple[Path, Tuple]] = []

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if not isinstance(message.subclass, Statistic):
            return
        if message.subclass.type != StatisticType.LogHealth:
            return
        logger.debug(f"Found health stat {message.subclass.value[0]} {message.subclass.value[1]} {message.file}")
        self.total_health.append((message.file, message.subclass.value))

    def report(self, report_table: "ReportTable") -> str:
        all_health_stats = []

        for file, health_tuple in self.total_health:
            health, reason = health_tuple
            all_health_stats.append(health)
            report_table.add_data(file, "Health Status", health.name)
            report_table.add_data(file, "Health Reason", reason)

        if all([EventLogHealth.Healthy == item for item in all_health_stats]):
            return f"{EventLogHealth.Healthy.name.upper()} - All event log files are healthy"
        if all([EventLogHealth.Bad == item for item in all_health_stats]):
            return f"{EventLogHealth.Bad.name.upper()} - All event log files are bad"
        healthy_usable_bools = Counter(
            [EventLogHealth.Healthy == item or EventLogHealth.Usable == item for item in all_health_stats]
        )
        if healthy_usable_bools[True]:
            return f"{EventLogHealth.Usable.name.upper()} - {healthy_usable_bools[True]}/{sum(healthy_usable_bools.values())} event log files are Healthy or Usable. Be careful of high crc segments"
        return "UNKNOWN - Log file health was not able to be determined"


class LogStatsReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.stats_list: Dict[Path, EventLogStats] = {}

    @property
    def total_stats(self):
        total_stats = EventLogStats()
        for stats in self.stats_list.values():
            total_stats += stats
        return total_stats

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if not isinstance(message.subclass, Statistic):
            return
        if message.subclass.type != StatisticType.LogStats:
            return
        logger.debug(f"Found Log stat {message.subclass.value} {message.file}")
        self.stats_list[message.file] = message.subclass.value

    def report(self, report_table: "ReportTable") -> str:
        for file, stats in self.stats_list.items():
            report_table.add_data(file, "CRC Err%", f"{stats.crc_error_rate:.2f}%")
            report_table.add_data(file, "Parse Err%", f"{stats.parse_error_rate:.2f}%")

        return str(self.total_stats)


class BadColumnCountReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        self.broken_lines: Dict[Path, int] = {}

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if not isinstance(message.subclass, Statistic):
            return
        if message.subclass.type != StatisticType.BadColumnLineCount:
            return
        file_name = message.file
        broken_lines = message.subclass.value
        self.broken_lines[file_name] = broken_lines

    def report(self, report_table: "ReportTable") -> str:
        for file, line_count in self.broken_lines.items():
            if line_count > 0:
                report_table.add_data(file, "Unparsable Line Count", str(line_count))
        return ""


class CrcSegmentReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.message_delete = False
        self.segment_crc: Dict[Path, List] = {}

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        message = get_line_item(split_line, "message")

        if "Previous segment had" not in message:
            return None

        message_split = message.split()
        errors = int(message_split[3])
        packets = int(message_split[7])
        logger.debug(f"found segment boundry {errors=} {packets=} {(errors / packets):.01%}")

        return_list = []
        error_rate = percentage(errors, packets)
        high_crc = error_rate > CONFIG["section_health"]["crc_error_rate"]["healthy"]
        segment_crc = Message(
            file, line_num, self.classname, Statistic(StatisticType.SegmentCrc, (high_crc, error_rate))
        )
        if high_crc:
            return_list.append(Message(file, line_num, self.classname, Action.StartDeleteSegment))
        return_list.extend([segment_crc, Message(file, line_num, self.classname, Action.StopDeleteSegment)])

        return return_list

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if isinstance(message.subclass, Statistic):
            if message.subclass.type != StatisticType.SegmentCrc:
                return

            if self.segment_crc.get(message.file) is None:
                self.segment_crc[message.file] = []
            self.segment_crc[message.file].append(message.subclass.value)

    def report(self, report_table: "ReportTable") -> str:
        for file, value_list in self.segment_crc.items():
            value_counter = Counter([value[0] for value in value_list])
            report_table.add_data(file, "Good Segment Count", f"{value_counter[False]}/{len(value_list)}")
        return ""


class FatalErrorReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.event_dict: Dict[str, Dict[str, Union[bool, int]]] = {}
        self.valid_subcomponents = ["Assert", "HW Error"]

        self.message_delete = False

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        sub_component = get_line_item(split_line, "subcomponent")
        if sub_component not in self.valid_subcomponents:
            return None

        core_name = get_line_item(split_line, "cpu_name")

        parameters = parse_parameters(get_line_item(split_line, "parameters"))

        if parameters.get("value") == 0:
            return None

        fatal_error = Message(file, line_num, self.classname, Error(core_name, sub_component, split_line))
        logger.debug(fatal_error.subclass.message(fatal_error))
        return [fatal_error]

    def filter_message_from_reversed_list(self, message: Message) -> Any:
        if isinstance(message.subclass, Action):
            if message.subclass == Action.StartDeleteSegment:
                self.message_delete = True
            if message.subclass == Action.StopDeleteSegment:
                self.message_delete = False

        if message.origin == self.classname and isinstance(message.subclass, Error):
            message.deleted = self.message_delete

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if message.origin != self.classname:
            return
        if not isinstance(message.subclass, Error):
            return
        if message.deleted:
            return

        if self.event_dict.get(message.subclass.core_name) is None:
            self.event_dict[message.subclass.core_name] = {}

        if self.event_dict[message.subclass.core_name].get(message.subclass.sub_component) is None:
            self.event_dict[message.subclass.core_name][message.subclass.sub_component] = 0

        self.event_dict[message.subclass.core_name][message.subclass.sub_component] += 1

    def report(self, report_table: "ReportTable") -> str:
        if not self.event_dict:
            return ""
        event_str_list = [f"{key}: {value}" for key, value in self.event_dict.items()]
        report_str = "  ".join(event_str_list)
        return report_str


class ParseErrorReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        self.decoder_hints: Dict[Path, int] = {}

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        return_messages = []
        if "ASIC String" in get_line_item(split_line, "message"):
            return_messages.append(Message(file, line_num, self.classname, Statistic(StatisticType.DecoderHint, 1)))
        return return_messages

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if message.origin != self.classname:
            return
        if not isinstance(message.subclass, Statistic):
            return
        if message.subclass.type == StatisticType.DecoderHint:
            if self.decoder_hints.get(message.file) is None:
                self.decoder_hints[message.file] = 0
            self.decoder_hints[message.file] += message.subclass.value

    def report(self, report_table: "ReportTable") -> str:
        for file, value in self.decoder_hints.items():
            report_table.add_data(file, "Decoder Hints", f"{value}")
        return ""


class PanicDumpReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        self.valid_subcomponents = ["Panic Dump"]
        self.panic_leader = ""
        self.panic_core = ""
        self.cores_dumped: set = set()

        self.message_delete = False

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        sub_component = get_line_item(split_line, "subcomponent")
        if sub_component not in self.valid_subcomponents:
            return None

        return_messages = []

        message = get_line_item(split_line, "message")
        core_name = get_line_item(split_line, "cpu_name")
        if "This CPU is the panic leader" in message:
            return [Message(file, line_num, self.classname, Statistic(StatisticType.PanicCoreLeader, core_name))]

        if "PANIC - Occurred" in message:
            return_messages.append(
                Message(file, line_num, self.classname, Statistic(StatisticType.CoresDumped, core_name))
            )

        if "Entered Crippled Mode" in message:
            return_messages.append(
                Message(file, line_num, self.classname, Error(core_name, "Entered Crippled Mode", split_line))
            )

        if "PANIC - Unhandled exception" in message:
            return_messages.append(
                Message(file, line_num, self.classname, Error(core_name, "Unhandled exception", split_line))
            )

        if "PANIC - Unhandled interrupt" in message:
            return_messages.append(
                Message(file, line_num, self.classname, Error(core_name, "Unhandled interrupt", split_line))
            )

        parameters_dict = parse_parameters(get_line_item(split_line, "parameters"))
        status_code = parameters_dict.get("STATUS_CODE")
        if status_code is not None:
            status_code_message = PANIC_STATUS_MESSAGES.get(status_code)
            status_code_message = status_code_message if status_code_message is not None else "Unknown Status Code"
            if status_code not in (0x50000004, 0x50000007):
                return_messages.extend(
                    [
                        Message(file, line_num, self.classname, Statistic(StatisticType.PanicedCore, core_name)),
                        Message(
                            file,
                            line_num,
                            self.classname,
                            Error(core_name, f"{sub_component} {status_code_message}", split_line),
                        ),
                    ]
                )

        return return_messages

    def filter_message_from_reversed_list(self, message: Message) -> Any:
        if isinstance(message.subclass, Action):
            if message.subclass == Action.StartDeleteSegment:
                self.message_delete = True
            if message.subclass == Action.StopDeleteSegment:
                self.message_delete = False

        if message.origin == self.classname:
            message.deleted = self.message_delete

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if not isinstance(message.subclass, Statistic):
            return
        if message.deleted:
            return

        if message.subclass.type == StatisticType.PanicCoreLeader:
            self.panic_leader = message.subclass.value
        elif message.subclass.type == StatisticType.PanicedCore:
            self.panic_core = message.subclass.value
        elif message.subclass.type == StatisticType.CoresDumped:
            self.cores_dumped.add(message.subclass.value)

    def report(self, report_table: "ReportTable") -> str:
        return_str = ""
        if self.panic_core:
            return_str += f"Panic Core: {self.panic_core}  Panic Leader: {self.panic_leader}  Cores Dumped: {len(self.cores_dumped)}"
        return return_str


class HifTimeoutReport(AbstractStatefulFilter):
    MAX_LOGS_TO_PRINT = 0

    def __init__(self) -> None:
        self.valid_subcomponents = ["HIF Command Timeout"]
        self.valid_messages = ["Pending Htag"]
        self.timed_out_htag: Set[str] = set()
        self.timed_out_opcode: Set[int] = set()
        self.logs_printed = 0

        self.message_delete = False

    def handle_subcomponent(self, sub_component: str, file: Path, line_num: int, line: List[str]):
        return_messages = []
        core_name = get_line_item(line, "cpu_name")
        return_messages.append(Message(file, line_num, self.classname, Error(core_name, sub_component, line)))

        parameters = parse_parameters(get_line_item(line, "parameters"))
        htag = parameters.get("HTAG")
        if htag is not None:
            return_messages.append(Message(file, line_num, self.classname, Statistic(StatisticType.TimedOutHtag, htag)))
        return return_messages

    def handle_message(self, message: str, file: Path, line_num: int, line: List[str]):
        return_messages = []
        parameters = parse_parameters(get_line_item(line, "parameters"))
        return_messages.append(
            Message(
                file,
                line_num,
                self.classname,
                Statistic(StatisticType.TimedOutOpcode, (parameters.get("HTAG"), parameters.get("NVME_OPCODE"))),
            )
        )
        return return_messages

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        returned_messages = []

        sub_component = get_line_item(split_line, "subcomponent")
        if sub_component in self.valid_subcomponents:
            returned_messages.extend(self.handle_subcomponent(sub_component, file, line_num, split_line))

        message = get_line_item(split_line, "message")
        if message in self.valid_messages:
            returned_messages.extend(self.handle_message(message, file, line_num, split_line))

        return returned_messages

    def filter_message_from_reversed_list(self, message: Message) -> Any:
        if isinstance(message.subclass, Action):
            if message.subclass == Action.StartDeleteSegment:
                self.message_delete = True
            if message.subclass == Action.StopDeleteSegment:
                self.message_delete = False

        if message.origin != self.classname:
            return

        if isinstance(message.subclass, Error):
            message.deleted = self.message_delete
        if isinstance(message.subclass, Statistic):
            if message.subclass.type in [StatisticType.TimedOutHtag, StatisticType.TimedOutOpcode]:
                message.deleted = self.message_delete

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if message.origin == self.classname and isinstance(message.subclass, Error):
            self.logs_printed += 1
            if self.logs_printed > HifTimeoutReport.MAX_LOGS_TO_PRINT:
                message.deleted = True

        if not isinstance(message.subclass, Statistic):
            return

        if message.subclass.type == StatisticType.TimedOutHtag:
            self.timed_out_htag.add(message.subclass.value)

        if message.subclass.type == StatisticType.TimedOutOpcode:
            htag, opcode = message.subclass.value
            if htag in self.timed_out_htag:
                self.timed_out_opcode.add(opcode)

    def report(self, report_table: "ReportTable") -> str:
        return_str = ""
        if not self.timed_out_htag:
            return return_str

        return_str += f"htag count: {len(self.timed_out_htag)}"

        return_str += "  opcode effected: "
        for opcode in self.timed_out_opcode:
            return_str += f"0x{opcode:02x} "

        return return_str


class CountStringsReport(AbstractStatefulFilter):
    def __init__(self) -> None:
        self.string_counts: Dict[str, int] = {}
        self.message_delete = False

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        for string in CONFIG["strings_to_count"]:
            if string in line:
                return [Message(file, line_num, self.classname, Statistic(StatisticType.CountedString, value=string))]
        return []

    def filter_message_from_reversed_list(self, message: Message) -> Any:
        if isinstance(message.subclass, Action):
            if message.subclass == Action.StartDeleteSegment:
                self.message_delete = True
            if message.subclass == Action.StopDeleteSegment:
                self.message_delete = False

        if message.origin != self.classname:
            return

        if isinstance(message.subclass, Statistic):
            if message.subclass.type in [StatisticType.CountedString]:
                message.deleted = self.message_delete

    def parse_message_from_forward_list(self, message: Message) -> Any:
        if not isinstance(message.subclass, Statistic):
            return
        if message.subclass.type != StatisticType.CountedString:
            return
        string = message.subclass.value
        if self.string_counts.get(string) is None:
            self.string_counts[string] = 0
        self.string_counts[string] += 1

    def report(self, report_table: "ReportTable"):
        out_str = ""
        for key, val in self.string_counts.items():
            out_str += f' "{key}": {val} '
        return out_str


class ReportTable:
    def __init__(self) -> None:
        self.data: Dict[Path, Dict[str, str]] = {}

    def add_data(self, file: Path, column: str, data: str):
        if self.data.get(file) is None:
            info, _, _ = EventLogNameInfo.from_file(file)
            self.data[file] = {"File Index": str(info.index)}

        self.data[file][column] = data

    def print(self, row_limit=5):
        table_str = ""

        widths = {}
        rows_to_report = list(self.data.keys())
        rows_to_report.sort()
        rows_to_report = rows_to_report[-row_limit:]

        for row in rows_to_report:
            row_dict = self.data[row]
            for column, data in row_dict.items():
                if widths.get(column) is None:
                    widths[column] = 0
                logger.debug(f"{widths}, {data}")
                widths[column] = max(len(column) + 2, len(str(data)) + 2, widths[column], len("unknown"))

        table_width = sum(widths.values()) + len(widths.values()) + 1
        spacer = "=" * table_width

        table_str += f"{spacer}\n"
        for column_name, width in widths.items():
            table_str += f"|{column_name: ^{width}}"
        table_str += "|\n"

        table_str += f"{spacer}\n"
        for file_path in rows_to_report:
            for column_name, width in widths.items():
                table_str += f"|{self.data[file_path].get(column_name, 'unknown'):^{width}}"
            table_str += "|\n"

        table_str += f"{spacer}\n"

        return table_str


def start_thread_to_terminate_when_parent_process_dies(parent_pid):
    pid = os.getpid()

    def check_parent_pid_or_kill_child_pid():
        while True:
            try:
                os.kill(parent_pid, 0)
            except OSError:
                logger.warning(f"KILLING child pid: {pid}")
                os.kill(pid, signal.SIGTERM)
            time.sleep(1)

    thread = threading.Thread(target=check_parent_pid_or_kill_child_pid, daemon=True)
    thread.start()


def _run_multiprocessed_filters(
    job_count: int,
    manager: SyncManager,
    log_file_objects: List[EventLogFile],
    filters: List[AbstractStatefulFilter],
    message_manager: MessageManager,
):
    job_count = min(job_count, len(log_file_objects))
    logger.info(f"Attempting to parse {len(log_file_objects)} event log file(s) with {job_count} jobs")

    with ProcessPoolExecutor(
        max_workers=job_count,
        initializer=start_thread_to_terminate_when_parent_process_dies,
        initargs=(os.getpid(),),
    ) as executor:
        event = manager.Event()
        try:
            futures: List[Future] = []
            for file_obj in log_file_objects:
                futures.append(executor.submit(file_obj.parse, event, filters))
            wait(futures)
        except KeyboardInterrupt:
            logger.warning("Shutting Down")
            event.set()
            executor.shutdown()
            for future in futures:
                future.cancel()
        finally:
            for future in futures:
                message_manager.add(future.result())


def _get_return_report(filters: List[AbstractStatefulFilter]):
    return_report = ""
    report_table = ReportTable()
    for filter in filters:
        report = filter.report(report_table)
        if isinstance(report, str) and report:
            report = report.strip()
            return_report += f"--- {filter.classname}: {report}\n"
    return_report += report_table.print(REPORT_TABLE_ROW_COUNT)
    return return_report


def _get_metric_string(log_file_objects: List[EventLogFile]):
    metric_file = None
    for file in log_file_objects:
        if file.health != EventLogHealth.Unparsable:
            metric_file = file
    return f"LOG_METRIC<(\n{metric_file.stats.log_metric if metric_file else 'unknown'}\n)>"


def _get_infra_metric_str(filters: List[AbstractStatefulFilter]):
    for filter in filters:
        if isinstance(filter, LogStatsReport):
            total_stats = filter.total_stats
        if isinstance(filter, FatalErrorReport):
            fatal_report = filter
    test_infra_metric = total_stats.test_infra_metric
    test_infra_metric.update(fatal_report.event_dict)
    return f"TEST_INFRA_METRIC<({test_infra_metric})>"


def parse_event_logs(event_logs: List[Path], output_writer: OutputWriter, job_count: int = 1, verbose: bool = False):
    message_manager = MessageManager()
    log_file_objects = [EventLogFile(file) for file in event_logs]

    filters: List[AbstractStatefulFilter] = [
        LogHealthReport(),
        LogStatsReport(),
        FatalErrorReport(),
        PanicDumpReport(),
        HifTimeoutReport(),
        CrcSegmentReport(),
        ParseErrorReport(),
        CountStringsReport(),
        BadColumnCountReport(),
    ]

    with Manager() as multiproc_manager:
        _run_multiprocessed_filters(job_count, multiproc_manager, log_file_objects, filters, message_manager)

    message_manager.reverse_filter(filters)
    message_manager.forward_parse(filters)

    errors = message_manager.errors(REPORT_MAX_ERROR_COUNT).strip()
    return_report = _get_return_report(filters)
    log_metric_str = _get_metric_string(log_file_objects)
    test_infra_metric_str = _get_infra_metric_str(filters)

    message_manager.debug_dump(output_writer, verbose)
    return errors, return_report, log_metric_str, test_infra_metric_str


def parse_hostlog_text(hostlog_file: Path, traceback_line_limit=15) -> Tuple[str, str]:
    logger.info(f"Parsing host log {hostlog_file}")
    last_ten_lines = []
    last_step = ""
    traceback_lines = []
    error = ""
    traceback_str_index = 0
    in_traceback = False

    with hostlog_file.open("r") as reader:
        for line in reader:
            line = line.replace("\n", "")
            if not line.strip():
                continue

            if "step" in line.lower():
                last_step = f"LAST STEP: {line}"

            last_ten_lines.append(line)
            last_ten_lines = last_ten_lines[-10:]

            if "Traceback (most recent call last)" in line:
                in_traceback = True
                traceback_str_index = line.index("Traceback (most recent call last)")
                logger.debug("Found traceback start")
                logger.debug(f"{traceback_str_index=} {in_traceback=} {line[traceback_str_index:]=}")
                traceback_lines.append(line)

            elif in_traceback:
                logger.debug(f"{line=}")
                traceback_lines.append(line)

                if line[traceback_str_index] != " ":
                    error = line[traceback_str_index:]
                    logger.info(f"Found error from traceback: {error}")
                    in_traceback = False
                    break

    return_str = last_step

    if not traceback_lines:
        traceback_lines = last_ten_lines.copy()
        traceback_lines.append("WARNING: Logs stopped without python traceback printed.")

    for line in traceback_lines[-traceback_line_limit:]:
        return_str += f"\n{line[traceback_str_index:]}"

    logger.info(f"Finished parsing host log {hostlog_file}")

    return error, return_str


def parse_host_logs(host_logs: List[Path]):
    if len(host_logs) > 1:
        logger.warning(f"Host logs only support parsing one file. Only parsing {host_logs[0]}")
    error, trace = parse_hostlog_text(host_logs[0], REPORT_MAX_TRACEBACK_LINES)
    return error, trace


def parse_args():
    """Parse the command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"Post Test Script for platform_fw fte testing FA. Version {__version__} ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-j",
        metavar="JOB_COUNT",
        type=type_job_count,
        default=1,
        help="the number of multi processes (jobs) to have (default: %(default)s)",
    )
    parser.add_argument(
        "-fw", "--fw_csv_event_logs", nargs="+", type=type_is_file, default=None, help="the FW csv files to parse"
    )
    parser.add_argument(
        "-fte",
        "--fte_python_host_log",
        nargs="+",
        type=type_is_file,
        default=None,
        help="the python host log file to parse",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w"),
        default="./pta_output.txt",
        help="the file to write triage notes too (default: %(default)s)",
    )
    parser.add_argument("--verbose", action="store_true", help="log more info")
    parser.add_argument("-v", "--version", action="version", version=__version__, help="show version info")
    parser.epilog = f"""
examples:
  python3 {Path(__file__).name} \
--fw_csv_event_logs /usr/local/micron/acme2/storage/artifacts/07234210_1/664f6808-53fa-11ee-93a4-a73c546d136b/20230915165919_666688d0_performance_fio/fwevent_log/decode/*.csv \
--fte_python_host_log /mnt/fw/artifacts/Automation/Jenkins/4_Cycle_LogResult/PEREGRINE/664f6808-53fa-11ee-93a4-a73c546d136b/performance_fio_666688d0/performance_fio.log \
--output output.txt -> command used in jfas
  python3 {Path(__file__).name} \
-fw *.csv \
-fte performance_fio.log \
-o output.txt \
-j all -> abreviated args with multiple jobs
"""

    return parser.parse_args()


def main():
    args = parse_args()
    setup_logger(args.verbose)
    logger.info(COMMAND_HEADER)

    exit_code = 0
    script_start_time = time.time()

    output_writer = OutputWriter(args.output)

    try:
        if args.fw_csv_event_logs:
            fw_error, report, log_metric, test_infra_metric = parse_event_logs(
                args.fw_csv_event_logs, output_writer, args.j, args.verbose
            )
            output_writer.add(fw_error, report, log_metric)
            output_writer.add(None, None, test_infra_metric)
        if args.fte_python_host_log:
            fte_error, trace = parse_host_logs(args.fte_python_host_log)
            output_writer.add(fte_error, trace, None)

    except Exception as ex:
        logger.exception(ex)
        args.output.write(f"{Path(__file__).name} hit fatal exception {str(ex)[-500:]}" + "\n")
        exit_code = 1
    finally:
        output_writer.commit()
        output_writer.write_line(COMMAND_HEADER)
        script_end_time = time.time()
        logger.info(f"Total Runtime: {script_end_time - script_start_time:0.2f}s")
        logger.info(f"Final output written to {args.output.name}")

    exit(exit_code)


if __name__ == "__main__":
    main()
