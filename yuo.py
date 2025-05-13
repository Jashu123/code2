Here's the complete code for the `LtssmAnalyzer` class with the revised confidence calculation:

```python
class LtssmAnalyzer(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.host_error_timestamps = []  # Timestamps from host logs (minute precision)
        self.host_error_seconds = []     # Full timestamps with seconds
        self.ltssm_state_changes = {}    # Dictionary of LTSSM changes keyed by wallclock_time

    def parse_hostlog_for_timestamps(self, hostlog_file: Path):
        """Parse host log file to extract timestamps before trace markers"""
        logger.info(f"Parsing host log {hostlog_file} for timestamps before trace markers")
        
        extracted_timestamps = []
        extracted_seconds = []
        previous_line_timestamp = None
        previous_line_full_timestamp = None
        
        with hostlog_file.open("r", errors="replace") as reader:
            for line in reader:
                line = line.strip()
                if not line:
                    continue
                
                # Try to extract full timestamp with seconds
                full_timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if full_timestamp_match:
                    previous_line_full_timestamp = full_timestamp_match.group(1)
                    previous_line_timestamp = previous_line_full_timestamp[:16]  # YYYY-MM-DD HH:MM
                else:
                    # Try for just minute precision
                    minute_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})', line)
                    if minute_match:
                        previous_line_timestamp = minute_match.group(1)
                        previous_line_full_timestamp = None
                
                # If this is the marker line and we have a timestamp
                if "log trace for debug [Start]" in line and previous_line_timestamp:
                    extracted_timestamps.append(previous_line_timestamp)
                    extracted_seconds.append(previous_line_full_timestamp)
                    logger.info(f"Found timestamp before trace marker: {previous_line_timestamp}")
        
        self.host_error_timestamps = extracted_timestamps
        self.host_error_seconds = extracted_seconds
        logger.info(f"Extracted {len(extracted_timestamps)} timestamps from host log")
        return extracted_timestamps

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        """Filter for LTSSM state changes in minutes of interest"""
        # Check if this is a PCIe LTSSM State Change message
        message = get_line_item(split_line, "message")
        if "PCIe LTSSM State Change" not in message:
            return None
        
        # Get LTSSM state
        parameters = get_line_item(split_line, "parameters")
        ltssm_state = None
        if "PCIE_LTSSM_STATE:" in parameters:
            ltssm_match = re.search(r'PCIE_LTSSM_STATE:\s*(0x[0-9A-Fa-f]+)', parameters)
            if ltssm_match:
                ltssm_state = ltssm_match.group(1)
        
        # Get timestamp
        wallclock_time = get_line_item(split_line, "wallclock_time")
        if not wallclock_time:
            return None
        
        # Convert to standard format
        standard_time = wallclock_time.replace('_', ' ')
        
        # Get minute part for matching
        minute_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})', standard_time)
        if not minute_match:
            return None
            
        time_key = minute_match.group(1)
        
        # Only process events in our minutes of interest
        if time_key in self.host_error_timestamps:
            ltssm_event = {
                'file': file,
                'line_num': line_num,
                'ltssm_state': ltssm_state,
                'full_timestamp': standard_time
            }
            
            return [Message(file, line_num, self.classname, Statistic(StatisticType.LtssmStateChange, ltssm_event))]
        
        return None

    def parse_message_from_forward_list(self, message: Message) -> Any:
        """Collect LTSSM events"""
        if not isinstance(message.subclass, Statistic) or message.subclass.type != StatisticType.LtssmStateChange:
            return
            
        ltssm_event = message.subclass.value
        standard_time = ltssm_event['full_timestamp']
        
        # Group by minute
        minute_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2})', standard_time)
        if minute_match:
            time_key = minute_match.group(1)
            
            if time_key not in self.ltssm_state_changes:
                self.ltssm_state_changes[time_key] = []
            
            self.ltssm_state_changes[time_key].append(ltssm_event)

    def extract_second(self, timestamp):
        """Extract second value from timestamp string"""
        if not timestamp:
            return None
            
        second_match = re.search(r':(\d{2})$', timestamp)
        if second_match:
            return int(second_match.group(1))
        return None

    def report(self, report_table: "ReportTable") -> str:
        """Generate simple report with count and proximity-based confidence level"""
        result = ["PCIe LTSSM State Change Analysis:"]
        
        total_timestamps = len(self.host_error_timestamps)
        total_with_changes = 0
        
        for i, minute in enumerate(self.host_error_timestamps):
            # Get events for this minute
            events = self.ltssm_state_changes.get(minute, [])
            count = len(events)
            
            # Try to extract second of interest
            host_second = self.extract_second(self.host_error_seconds[i]) if i < len(self.host_error_seconds) else None
            
            # Basic count information
            if host_second is not None:
                result.append(f"Host Timestamp {minute} (Second of Interest: :{host_second:02d}): {count} LTSSM state changes")
            else:
                result.append(f"Host Timestamp {minute}: {count} LTSSM state changes")
            
            if count > 0:
                total_with_changes += 1
                
                if host_second is not None:
                    # Count events by second for better reporting
                    second_counts = {}
                    for evt in events:
                        evt_sec = self.extract_second(evt['full_timestamp'])
                        if evt_sec is not None:
                            if evt_sec not in second_counts:
                                second_counts[evt_sec] = 0
                            second_counts[evt_sec] += 1
                    
                    # Calculate confidence based on proximity to second of interest
                    total_proximity = 0
                    total_events = 0
                    
                    for sec, count_at_sec in second_counts.items():
                        # Calculate distance between this second and the second of interest
                        # For 60-second range: 0 seconds distance = 100%, 59 seconds = 1.7%
                        distance = abs(sec - host_second)
                        proximity_pct = max(0, 100 - (distance * 100 / 60))
                        
                        # Add to total, weighted by number of events at this second
                        total_proximity += proximity_pct * count_at_sec
                        total_events += count_at_sec
                    
                    # Calculate weighted average confidence
                    if total_events > 0:
                        confidence = total_proximity / total_events
                        
                        # Log the most common seconds for transparency
                        most_common_seconds = sorted(second_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                        seconds_info = ", ".join([f":{sec:02d} ({count})" for sec, count in most_common_seconds])
                        result.append(f"  Most common seconds: {seconds_info}")
                        
                        # Report final confidence
                        result.append(f"  Confidence Level: {confidence:.0f}% (based on proximity to Second of Interest :{host_second:02d})")
                        
                        # Add to report table
                        report_table.add_data(
                            Path("summary"),
                            "LTSSM Analysis",
                            f"Second :{host_second:02d}, {confidence:.0f}% confidence"
                        )
                    else:
                        result.append("  Confidence: N/A (could not extract seconds from events)")
                else:
                    result.append("  Confidence: N/A (second of interest not available)")
    
        # Summary line
        result.insert(1, f"Summary: Found {total_with_changes}/{total_timestamps} timestamps with LTSSM changes")
        
        return "\n".join(result)
```

Now let's add the function to use this class in the main script processing flow:

```python
def parse_logs_with_ltssm_analysis(event_logs: List[Path], host_logs: List[Path], output_writer: OutputWriter, job_count: int = 1, verbose: bool = False):
    """Parse both event logs and host logs with LTSSM analysis"""
    message_manager = MessageManager()
    log_file_objects = [EventLogFile(file) for file in event_logs]

    # Create the LTSSM analyzer
    ltssm_analyzer = LtssmAnalyzer()
    
    # First parse the host logs to get timestamps
    if host_logs:
        for host_log in host_logs:
            ltssm_analyzer.parse_hostlog_for_timestamps(host_log)
    else:
        logger.warning("No host logs provided for LTSSM analysis")
    
    # Combine standard filters with our LTSSM analyzer
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
        ltssm_analyzer,  # Add our LTSSM analyzer
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
```

And for completeness, also make sure to include the necessary addition to the StatisticType enum:

```python
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
    LtssmStateChange = auto()  # Add this new type
```

Finally, update the main function to use our new parsing function:

```python
def main():
    args = parse_args()
    setup_logger(args.verbose)
    logger.info(COMMAND_HEADER)

    exit_code = 0
    script_start_time = time.time()

    output_writer = OutputWriter(args.output)

    try:
        if args.fw_csv_event_logs and args.fte_python_host_log:
            # Use the integrated parsing when both log types are available
            fw_error, report, log_metric, test_infra_metric = parse_logs_with_ltssm_analysis(
                args.fw_csv_event_logs, args.fte_python_host_log, output_writer, args.j, args.verbose
            )
            output_writer.add(fw_error, report, log_metric)
            output_writer.add(None, None, test_infra_metric)
        elif args.fw_csv_event_logs:
            # Just process firmware logs
            fw_error, report, log_metric, test_infra_metric = parse_event_logs(
                args.fw_csv_event_logs, output_writer, args.j, args.verbose
            )
            output_writer.add(fw_error, report, log_metric)
            output_writer.add(None, None, test_infra_metric)
        elif args.fte_python_host_log:
            # Just process host logs
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
```

With these changes, the script should now:

1. Extract timestamps from host logs
2. Find LTSSM state changes in the firmware logs at those timestamps
3. Calculate a confidence level based on how close the LTSSM events are to the second of interest
4. Show the most common seconds where LTSSM events occurred
5. Report the results in a concise format

For your specific example, events at second :01 with a second of interest of :41 should give a confidence level around 31-33%, which matches your expectation.​​​​​​​​​​​​​​​​