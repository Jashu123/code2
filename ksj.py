def parse_hostlog_text(hostlog_file: Path, traceback_line_limit=15) -> Tuple[str, str]:
    """
    Enhanced version that includes both original parsing and PCIe error analysis
    """
    logger.info(f"Parsing host log {hostlog_file}")
    
    # Original parsing logic
    last_ten_lines = []
    last_step = ""
    traceback_lines = []
    error = ""
    traceback_str_index = 0
    in_traceback = False
    non_block_failures = []  # Track non-block failures

    with hostlog_file.open("r") as reader:
        for line in reader:
            line = line.replace("\n", "")
            if not line.strip():
                continue

            if "step" in line.lower():
                last_step = f"LAST STEP: {line}"

            # Capture non-block failures
            if "non-block failure" in line.lower() or "non block failure" in line.lower():
                non_block_failures.append(line)

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
        # No traceback found - check for non-block failures
        if non_block_failures:
            # Put non-block failures in ERROR (goes to top)
            error = "NON-BLOCK FAILURES DETECTED (No Python Traceback Found)\n"
            error += "=" * 60 + "\n"
            for failure in non_block_failures[-10:]:  # Show last 10 non-block failures
                error += f"{failure}\n"
            error += "=" * 60
            # Put minimal info in return_str (goes below table)
            return_str += "\n\n(Non-block failures printed above)"
        else:
            # No traceback, no non-block failures - use last 10 lines
            traceback_lines = last_ten_lines.copy()
            traceback_lines.append("WARNING: Logs stopped without python traceback printed.")
            
            for line in traceback_lines[-traceback_line_limit:]:
                return_str += f"\n{line}"
    else:
        # Traceback found - ORIGINAL BEHAVIOR (goes to return_str, printed below table)
        for line in traceback_lines[-traceback_line_limit:]:
            return_str += f"\n{line[traceback_str_index:]}"

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
        # Continue with original functionality if PCIe analysis fails

    logger.info(f"Finished parsing host log {hostlog_file}")

    return error, return_str
