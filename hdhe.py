def parse_hostlog_text(hostlog_file: Path, traceback_line_limit=15) -> Tuple[str, str]:
    """
    Enhanced version that includes both original parsing and PCIe error analysis
    """
    logger.info(f"Parsing host log {hostlog_file}")
    
    last_ten_lines = []
    last_step = ""
    traceback_lines = []
    error = ""
    traceback_str_index = 0
    in_traceback = False
    
    # NEW: Variables for non-blocking failures
    non_blocking_failures = []
    in_non_blocking_section = False
    found_non_blocking_section = False

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
        # NEW: Look for NON-BLOCKING FAILURES section from bottom up
        logger.info("No traceback found, looking for NON-BLOCKING FAILURES section")
        
        with hostlog_file.open("r") as reader:
            all_lines = reader.readlines()
        
        # Read from bottom to top
        for i in range(len(all_lines) - 1, -1, -1):
            line = all_lines[i].strip()
            
            # Stop when we hit JOURNALCTL OUTPUT (end of non-blocking section)
            if "JOURNALCTL OUTPUT" in line:
                in_non_blocking_section = True
                continue
            
            # When we find NON-BLOCKING FAILURES, we've reached the start
            if "NON-BLOCKING FAILURES" in line and in_non_blocking_section:
                found_non_blocking_section = True
                break
            
            # Collect FAILURE lines while in the section
            if in_non_blocking_section and "FAILURE:" in line:
                non_blocking_failures.append(line)
        
        # Reverse to get correct order and limit to 3 lines
        non_blocking_failures = non_blocking_failures[::-1][:3]
        
        if found_non_blocking_section and non_blocking_failures:
            logger.info(f"Found {len(non_blocking_failures)} non-blocking failures")
            traceback_lines = ["NON-BLOCKING FAILURES DETECTED:"] + non_blocking_failures
            error = f"NON-BLOCKING FAILURES: {len(non_blocking_failures)} failure(s) detected"
        else:
            traceback_lines = last_ten_lines.copy()
            traceback_lines.append("WARNING: Logs stopped without python traceback printed.")

    for line in traceback_lines[-traceback_line_limit:]:
        if isinstance(line, str) and len(line) > traceback_str_index:
            return_str += f"\n{line[traceback_str_index:]}"
        else:
            return_str += f"\n{line}"

    # Add PCIe error analysis
    try:
        pcie_summary, pcie_detailed = analyze_pcie_errors_in_hostlog(hostlog_file)
        
        # Combine the reports
        if pcie_summary:
            error = f"{error}\n{pcie_summary}" if error else pcie_summary
        
        if pcie_detailed:
            return_str = f"{return_str}\n\n{'='*80}\nPCIe ERROR ANALYSIS:\n{pcie_detailed}"
    except Exception as e:
        logger.warning(f"PCIe error analysis failed: {e}")

    logger.info(f"Finished parsing host log {hostlog_file}")

    return error, return_str
