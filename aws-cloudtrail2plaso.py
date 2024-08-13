#!/usr/bin/env python3
"""
Script Name: aws-cloudtrail2plaso.py
Author: Kevin Stokes
Date Created: 2024-08-12
Last Modified: 2024-08-12
Description: Processes CloudTrail JSON files and converts them to Plaso-compatible JSONL format associated with lookup-events.
Lookup-Events Ref: https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/lookup-events.html
Sample Data to parse: https://github.com/invictus-ir/aws_dataset
"""

import os
import gzip
import json
import argparse
from datetime import datetime, timezone

# Function to read and parse a CloudTrail JSON log file
def read_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Function to read and parse a CloudTrail JSONL log file
def read_jsonl_file(file_path):
    records = []
    with open(file_path, 'r') as f:
        for line in f:
            records.append(json.loads(line))
    return {'Records': records}

# Function to read and parse a GZ (gzip compressed) CloudTrail log file
def read_gz_file(file_path):
    with gzip.open(file_path, 'rt') as f:
        content = f.read()
        # Check if the file is JSONL.gz or JSON.gz
        if file_path.endswith('.jsonl.gz'):
            records = [json.loads(line) for line in content.splitlines()]
            return {'Records': records}
        else:
            return json.loads(content)

# Function to read all JSON, JSONL, and GZ files from a directory and aggregate their records
def read_files_from_directory(directory_path):
    all_records = {}
    file_paths = []
    # Traverse the directory and collect all file paths
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_paths.append(os.path.join(root, file))

    total_files = len(file_paths)
    total_records = 0
    # Process each file based on its extension and aggregate the records
    for index, file_path in enumerate(file_paths):
        if file_path.endswith('.json'):
            records = read_json_file(file_path)['Records']
        elif file_path.endswith('.jsonl'):
            records = read_jsonl_file(file_path)['Records']
        elif file_path.endswith('.gz'):
            records = read_gz_file(file_path)['Records']
        else:
            continue

        for record in records:
            all_records[record['eventID']] = record

        total_records += len(records)
        print(f'Processed {index + 1} of {total_files} files: {file_path}')

    unique_records = len(all_records)
    duplicates_removed = total_records - unique_records

    print(f'Total records processed: {total_records}')
    print(f'Unique records found: {unique_records}')
    print(f'Duplicates removed: {duplicates_removed}')

    return {'Records': list(all_records.values())}

# Function to convert event time to a specific local format
def convert_event_time_to_local(event_time_str):
    utc_time = datetime.strptime(event_time_str, '%Y-%m-%dT%H:%M:%SZ')
    utc_time = utc_time.replace(tzinfo=timezone.utc)
    local_time_str = utc_time.isoformat().replace('T', ' ')[:-6]
    return local_time_str + '+00:00'

# Function to convert CloudTrail data to a format compatible with Plaso
def convert_cloudtrail_to_plaso(cloudtrail_data):
    events = []
    for record in cloudtrail_data['Records']:
        event_time_utc = record['eventTime']
        event_time_local = convert_event_time_to_local(event_time_utc)

        event = {
            'EventId': record['eventID'],
            'EventName': record['eventName'],
            'ReadOnly': str(record['readOnly']).lower(),
            'AccessKeyId': record['userIdentity'].get('accessKeyId', ''),
            'EventTime': event_time_local,
            'EventSource': record['eventSource'],
            'Username': record['userIdentity'].get('userName', ''),
            'Resources': [
                {
                    'ResourceType': resource.get('type', 'Unknown'),
                    'ResourceName': resource.get('ARN', 'Unknown')
                } for resource in record.get('resources', [])
            ],
            'CloudTrailEvent': json.dumps(record).replace('\n', '').replace('\t', '').replace(' ', '')
        }
        events.append(event)
    return events

# Function to write events to JSONL files, splitting them if necessary
def write_events_to_jsonl(events, output_filepath):
    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    file_index = 0
    line_count = 0
    output_file = None
    multiple_files = len(events) > 500000

    for event in events:
        # Split the file if it reaches 500,000 lines
        if line_count % 500000 == 0:
            if output_file:
                output_file.close()
            file_index += 1
            if multiple_files:
                current_output_filepath = f"{output_filepath}_part{file_index}"
            else:
                current_output_filepath = f"{output_filepath}"
            output_file = open(current_output_filepath, 'w')

        output_file.write(json.dumps(event) + '\n')
        line_count += 1

    if output_file:
        output_file.close()

# Main function to parse arguments and process the CloudTrail data
def main():
    parser = argparse.ArgumentParser(description='Process CloudTrail JSON files and convert them to Plaso-compatible JSONL format.')
    parser.add_argument('input_directory', type=str, help='Path to the directory containing CloudTrail JSON, JSONL, or GZ files.')
    parser.add_argument('output_filepath', type=str, help='Path and base name for the output JSONL file(s).')

    args = parser.parse_args()

    # Read and aggregate records from the input directory
    cloudtrail_data = read_files_from_directory(args.input_directory)
    # Convert aggregated CloudTrail data to Plaso-compatible format
    events = convert_cloudtrail_to_plaso(cloudtrail_data)
    # Write the converted events to JSONL files
    write_events_to_jsonl(events, args.output_filepath)

if __name__ == "__main__":
    main()
