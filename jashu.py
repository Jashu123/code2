class PcieLtssmStateChangeDetector(AbstractStatefulFilter):
    def __init__(self) -> None:
        super().__init__()
        self.host_error_timestamps = []
        self.ltssm_state_changes = {}  # Dictionary keyed by wallclock_time
        self.correlated_events = []

    def parse_hostlog_for_errors(self, hostlog_file: Path):
        """Parse host log file for error timestamps before log trace markers"""
        logger.info(f"Parsing host log {hostlog_file} for error timestamps")
        
        error_timestamp = None
        with hostlog_file.open("r", errors="replace") as reader:
            for line in reader:
                line = line.strip()
                if not line:
                    continue
                
                # Look for timestamp pattern at the beginning of the line
                timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if timestamp_match:
                    # If line contains ERROR, save the timestamp
                    if "ERROR" in line:
                        error_timestamp = timestamp_match.group(1)
                        logger.debug(f"Found error timestamp: {error_timestamp}")
                        self.host_error_timestamps.append(error_timestamp)
                        
                # Check if this is the log trace marker line
                if "log trace for debug [Start]" in line:
                    # Reset for next occurrence
                    error_timestamp = None
        
        logger.info(f"Found {len(self.host_error_timestamps)} error timestamps in host log")
        return self.host_error_timestamps

    def parse_event(self, file: Path, line_num: int, line: str, split_line: List[str]) -> Optional[List["Message"]]:
        """Process firmware log lines for LTSSM state changes"""
        # Check if this is a PCIe LTSSM State Change message
        message = get_line_item(split_line, "message")
        if "PCIe LTSSM State Change" not in message:
            return None
            
        # Extract the LTSSM state from parameters
        parameters = get_line_item(split_line, "parameters")
        ltssm_state = None
        if "PCIE_LTSSM_STATE:" in parameters:
            # Extract the LTSSM state value
            ltssm_match = re.search(r'PCIE_LTSSM_STATE:\s*(0x[0-9A-Fa-f]+)', parameters)
            if ltssm_match:
                ltssm_state = ltssm_match.group(1)
            
        # Get the wallclock time from the log entry
        wallclock_time = get_line_item(split_line, "wallclock_time")
        if not wallclock_time:
            return None
            
        # Store the LTSSM state change event
        ltssm_event = {
            'file': file,
            'line_num': line_num,
            'ltssm_state': ltssm_state,
            'raw_line': line,
            'power_cycle_time': get_line_item(split_line, "power_cycle_time_formatted")
        }
        
        # Group by wallclock_time
        if wallclock_time not in self.ltssm_state_changes:
            self.ltssm_state_changes[wallclock_time] = []
        
        self.ltssm_state_changes[wallclock_time].append(ltssm_event)
        
        return [Message(file, line_num, self.classname, Statistic(StatisticType.LtssmStateChange, ltssm_event))]

    def find_suspicious_patterns(self):
        """Find timestamps with multiple LTSSM state changes"""
        suspicious_patterns = {}
        
        for wallclock_time, events in self.ltssm_state_changes.items():
            if len(events) > 1:
                suspicious_patterns[wallclock_time] = events
                
        return suspicious_patterns

    def correlate_with_host_errors(self):
        """Correlate suspicious LTSSM patterns with host errors"""
        suspicious_patterns = self.find_suspicious_patterns()
        if not suspicious_patterns:
            logger.info("No suspicious LTSSM patterns found")
            return []
            
        logger.info(f"Found {len(suspicious_patterns)} timestamps with multiple LTSSM state changes")
        
        correlated_events = []
        for wallclock_time, ltssm_events in suspicious_patterns.items():
            # Convert wallclock_time to a datetime
            try:
                fw_time = datetime.strptime(wallclock_time.replace('_', ' '), '%Y-%m-%d %H:%M:%S')
                
                # Find closest host error timestamp
                closest_error = None
                closest_diff = float('inf')
                
                for error_time_str in self.host_error_timestamps:
                    try:
                        error_time = datetime.strptime(error_time_str, '%Y-%m-%d %H:%M:%S')
                        time_diff = abs((fw_time - error_time).total_seconds())
                        
                        if time_diff < closest_diff:
                            closest_diff = time_diff
                            closest_error = error_time_str
                    except ValueError:
                        continue
                
                correlated_events.append({
                    'wallclock_time': wallclock_time,
                    'ltssm_events': ltssm_events,
                    'closest_error': closest_error,
                    'time_diff_seconds': closest_diff if closest_error else None
                })
            except ValueError:
                logger.warning(f"Failed to parse wallclock time: {wallclock_time}")
                
        return correlated_events

    def parse_message_from_forward_list(self, message: Message) -> Any:
        # This is called after all parsing is done
        if not isinstance(message.subclass, Statistic) or message.subclass.type != StatisticType.LtssmStateChange:
            return
            
        # Already processed in parse_event method

    def report(self, report_table: "ReportTable") -> str:
        # Find suspicious patterns and correlate with host errors
        self.correlated_events = self.correlate_with_host_errors()
        
        if not self.correlated_events:
            return "No suspicious PCIe LTSSM state change patterns found"
            
        result = ["Suspicious PCIe LTSSM State Changes (multiple changes at same timestamp):"]
        
        for i, event in enumerate(self.correlated_events):
            wallclock_time = event['wallclock_time']
            ltssm_events = event['ltssm_events']
            closest_error = event['closest_error']
            time_diff = event['time_diff_seconds']
            
            result.append(f"\n[{i+1}] Timestamp: {wallclock_time} - {len(ltssm_events)} state changes:")
            
            # Print LTSSM state sequence
            state_sequence = []
            for evt in ltssm_events:
                state_sequence.append(f"{evt['ltssm_state']}")
                
            result.append(f"  LTSSM State Sequence: {' → '.join(state_sequence)}")
            
            # Show the events
            for j, evt in enumerate(ltssm_events):
                result.append(f"  [{j+1}] State: {evt['ltssm_state']} - "
                             f"Power Cycle Time: {evt['power_cycle_time']} - "
                             f"File: {evt['file'].name}:{evt['line_num']}")
            
            # Link to host error if found
            if closest_error and time_diff is not None:
                correlation_quality = "Strong" if time_diff <= 10 else "Moderate" if time_diff <= 30 else "Weak"
                result.append(f"  Closest Host Error: {closest_error} ({time_diff:.1f}s difference - {correlation_quality} correlation)")
            else:
                result.append("  No related host error found")
        
        # Add summary to the report table
        report_table.add_data(
            Path("summary"), 
            "Suspicious LTSSM Changes", 
            f"{len(self.correlated_events)} timestamps with multiple state changes"
        )
        
        # Add some details to the report table
        for i, event in enumerate(self.correlated_events[:3]):  # First 3 for brevity
            wallclock_time = event['wallclock_time']
            ltssm_count = len(event['ltssm_events'])
            state_sequence = " → ".join([evt['ltssm_state'] for evt in event['ltssm_events']])
            
            report_table.add_data(
                Path("LTSSM_details"), 
                f"Pattern {i+1}", 
                f"{wallclock_time}: {ltssm_count} changes ({state_sequence})"
            )
            
            # If correlated with host error
            if event['closest_error']:
                time_diff = event['time_diff_seconds']
                correlation_quality = "Strong" if time_diff <= 10 else "Moderate" if time_diff <= 30 else "Weak"
                report_table.add_data(
                    Path("LTSSM_details"),
                    f"Correlation {i+1}",
                    f"Host error at {event['closest_error']} ({time_diff:.1f}s diff, {correlation_quality})"
                )
        
        return "\n".join(result)
