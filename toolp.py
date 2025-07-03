#!/usr/bin/env python3
"""
CSV Test Argument Manager

A tool to add/remove test run arguments from Master CSV based on specified criteria.
Supports flexible filtering and argument manipulation for test management.
"""

import csv
import argparse
import sys
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


class CSVTestManager:
    def __init__(self, csv_file: str):
        """Initialize the CSV Test Manager with the path to the CSV file."""
        self.csv_file = Path(csv_file)
        self.data = []
        self.headers = []
        self.load_csv()
    
    def load_csv(self):
        """Load CSV data into memory."""
        try:
            with open(self.csv_file, 'r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                self.headers = reader.fieldnames
                self.data = list(reader)
            print(f"INFO: Loaded {len(self.data)} rows from {self.csv_file}")
        except FileNotFoundError:
            print(f"ERROR: File {self.csv_file} not found!")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Loading CSV failed - {e}")
            sys.exit(1)
    
    def save_csv(self, backup: bool = True):
        """Save the modified data back to CSV file."""
        if backup:
            backup_file = self.csv_file.with_suffix('.bak')
            self.csv_file.rename(backup_file)
            print(f"INFO: Backup created at {backup_file}")
        
        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=self.headers)
                writer.writeheader()
                writer.writerows(self.data)
            print(f"INFO: Changes saved to {self.csv_file}")
        except Exception as e:
            print(f"ERROR: Saving CSV failed - {e}")
            sys.exit(1)
    
    def filter_rows(self, criteria: Dict[str, str]) -> List[Dict[str, Any]]:
        """Filter rows based on criteria dictionary."""
        filtered_rows = []
        for row in self.data:
            match = True
            for column, value in criteria.items():
                if column not in row:
                    print(f"WARNING: Column '{column}' not found in CSV")
                    match = False
                    break
                if row[column].strip() != value.strip():
                    match = False
                    break
            if match:
                filtered_rows.append(row)
        
        print(f"INFO: Found {len(filtered_rows)} rows matching criteria")
        return filtered_rows
    
    def add_argument(self, criteria: Dict[str, str], argument: str, target_column: str = "Base Args"):
        """Add argument to rows matching criteria."""
        filtered_rows = self.filter_rows(criteria)
        
        if not filtered_rows:
            print(f"WARNING: No rows found matching criteria")
            return
        
        print(f"INFO: Adding argument '{argument}' to matching tests")
        
        modified_count = 0
        skipped_count = 0
        
        for row in filtered_rows:
            current_args = row.get(target_column, "").strip()
            
            # Handle special case for --test_function_name=TestName
            if argument == "--test_function_name=TestName":
                test_name = row.get("Test Name", "")
                if test_name:
                    actual_argument = f"--test_function_name={test_name}"
                    # Check if this specific test function name already exists
                    if actual_argument in current_args:
                        skipped_count += 1
                        continue
                else:
                    print(f"WARNING: No Test Name found for row, skipping")
                    skipped_count += 1
                    continue
            else:
                actual_argument = argument
                # Check if argument already exists
                if argument in current_args:
                    skipped_count += 1
                    continue
            
            # Add the argument
            if current_args:
                row[target_column] = f"{current_args} {actual_argument}"
            else:
                row[target_column] = actual_argument
            
            modified_count += 1
        
        print(f"INFO: Modified {modified_count} tests, skipped {skipped_count} (already had argument)")
        
        if modified_count == 0:
            print(f"INFO: No changes needed - all matching tests already have the argument")
    
    def remove_argument(self, criteria: Dict[str, str], argument_pattern: str, target_column: str = "Base Args"):
        """Remove argument from rows matching criteria."""
        filtered_rows = self.filter_rows(criteria)
        
        if not filtered_rows:
            print(f"WARNING: No rows found matching criteria")
            return
        
        print(f"INFO: Removing argument '{argument_pattern}' from matching tests")
        
        modified_count = 0
        for row in filtered_rows:
            current_args = row.get(target_column, "").strip()
            
            if not current_args:
                continue
            
            # Handle different argument patterns
            if argument_pattern == "--test_function_name=TestName":
                # Remove any --test_function_name= argument
                pattern = r'--test_function_name=\S+'
            else:
                # Exact match or pattern
                pattern = re.escape(argument_pattern)
            
            # Remove the argument
            new_args = re.sub(pattern, '', current_args)
            new_args = re.sub(r'\s+', ' ', new_args).strip()  # Clean up extra spaces
            
            if new_args != current_args:
                row[target_column] = new_args
                modified_count += 1
        
        print(f"INFO: Modified {modified_count} tests")
        
        if modified_count == 0:
            print(f"INFO: No changes needed - no matching tests had the argument")
    
    def list_matching_rows(self, criteria: Dict[str, str]):
        """List rows that match the criteria."""
        filtered_rows = self.filter_rows(criteria)
        
        if not filtered_rows:
            return
        
        print(f"INFO: Listing {len(filtered_rows)} matching tests:")
        for i, row in enumerate(filtered_rows, 1):
            test_name = row.get('Test Name', 'Unknown')
            current_args = row.get('Base Args', '')
            print(f"  {i:2d}. {test_name}")
            if current_args:
                print(f"      Args: {current_args}")
            print()  # Add blank line for readability
    
    def show_available_columns(self):
        """Show all available columns in the CSV."""
        print(f"INFO: Available columns ({len(self.headers)} total):")
        for i, header in enumerate(self.headers, 1):
            print(f"  {i:2d}. {header}")


def parse_criteria(criteria_str: str) -> Dict[str, str]:
    """Parse criteria string into dictionary."""
    criteria = {}
    if criteria_str:
        for item in criteria_str.split(','):
            if '=' in item:
                key, value = item.split('=', 1)
                criteria[key.strip()] = value.strip()
            else:
                print(f"WARNING: Invalid criteria format '{item}'. Use key=value format.")
    return criteria


def main():
    parser = argparse.ArgumentParser(
        description="Add/remove test run arguments from Master CSV based on criteria",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add --test_function_name=TestName for all tests with Pool=Feature
  %(prog)s master.csv add --criteria "Pool=Feature" --argument "--test_function_name=TestName"
  
  # Add --vssr_enable for all tests with Pool=Feature
  %(prog)s master.csv add --criteria "Pool=Feature" --argument "--vssr_enable"
  
  # Add --stress_test for all tests with Pool=IO
  %(prog)s master.csv add --criteria "Pool=IO" --argument "--stress_test"
  
  # Remove --test_function_name arguments for all tests with Pool=Feature
  %(prog)s master.csv remove --criteria "Pool=Feature" --argument "--test_function_name=TestName"
  
  # List all tests with Pool=Feature
  %(prog)s master.csv list --criteria "Pool=Feature"
  
  # Show available columns
  %(prog)s master.csv columns
        """
    )
    
    parser.add_argument('csv_file', help='Path to the Master CSV file')
    parser.add_argument('action', choices=['add', 'remove', 'list', 'columns'],
                      help='Action to perform')
    parser.add_argument('--criteria', help='Filter criteria (e.g., "Pool=Feature,Category=FE")')
    parser.add_argument('--argument', help='Argument to add/remove (e.g., "--vssr_enable")')
    parser.add_argument('--column', default='Base Args', 
                      help='Target column (default: Base Args)')
    parser.add_argument('--no-backup', action='store_true',
                      help='Skip creating backup file')
    
    args = parser.parse_args()
    
    # Initialize the CSV manager
    manager = CSVTestManager(args.csv_file)
    
    if args.action == 'columns':
        manager.show_available_columns()
        return
    
    if args.action == 'list':
        if not args.criteria:
            print("ERROR: --criteria is required for list action")
            sys.exit(1)
        criteria = parse_criteria(args.criteria)
        manager.list_matching_rows(criteria)
        return
    
    if args.action in ['add', 'remove']:
        if not args.criteria:
            print(f"ERROR: --criteria is required for {args.action} action")
            sys.exit(1)
        if not args.argument:
            print(f"ERROR: --argument is required for {args.action} action")
            sys.exit(1)
        
        criteria = parse_criteria(args.criteria)
        
        if args.action == 'add':
            manager.add_argument(criteria, args.argument, args.column)
        else:  # remove
            manager.remove_argument(criteria, args.argument, args.column)
        
        # Save the changes
        manager.save_csv(backup=not args.no_backup)
        print(f"INFO: Operation completed successfully")


if __name__ == "__main__":
    main()