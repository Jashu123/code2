I'll simplify the table entry to only show the second of interest and confidence level:

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
                    # Calculate proximity as a percentage
                    # 100% = all events at exact second, 0% = all events at furthest possible second (30 sec)
                    max_distance = 30  # Maximum possible distance within a minute
                    
                    # Calculate distance of each event from the host second
                    total_proximity = 0
                    valid_events = 0
                    
                    for evt in events:
                        evt_sec = self.extract_second(evt['full_timestamp'])
                        if evt_sec is not None:
                            distance = abs(evt_sec - host_second)
                            # Convert distance to proximity percentage
                            # 0 seconds distance = 100% proximity
                            # max_distance or more = 0% proximity
                            proximity = max(0, 100 - (distance * 100 / max_distance))
                            total_proximity += proximity
                            valid_events += 1
                    
                    # Calculate average proximity percentage
                    if valid_events > 0:
                        confidence = total_proximity / valid_events
                        result.append(f"  Confidence Level: {confidence:.0f}% (based on proximity to Second of Interest :{host_second:02d})")
                        
                        # Add to report table - simplified to just show second of interest and confidence
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

The report table entry is now simplified to only show the second of interest and the confidence level in a clean format:

```
Second :22, 85% confidence
```

This provides just the essential information you requested without any additional details in the table entry.​​​​​​​​​​​​​​​​