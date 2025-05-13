I understand now. You want to calculate the confidence level based on how close the LTSSM occurrences are to the second of interest, where:

1. The second of interest is considered the maximum (100% confidence)
2. Events occurring exactly at the second of interest get 100% confidence
3. Events occurring farther away from the second of interest get proportionally lower confidence
4. The calculation considers the full 60-second range within the minute

Let me revise the calculation to match this approach:

```python
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

With this revised approach:

1. For the second of interest (:41 in your example):
   - Events at second :41 get 100% proximity
   - Events at second :40 or :42 get 98.3% proximity (1 second away)
   - Events at second :01 get 33.3% proximity (40 seconds away)
   - Events at second :11 get 50% proximity (30 seconds away)

2. The final confidence percentage is a weighted average based on how many events occur at each second

For your specific example with most events at second :01 and the second of interest at :41, the confidence level should be around 33%, which is closer to the 31% you were expecting.

The report will now also show the most common seconds and their counts, which will help explain the confidence calculation and provide more insight into where the LTSSM events are occurring.​​​​​​​​​​​​​​​​