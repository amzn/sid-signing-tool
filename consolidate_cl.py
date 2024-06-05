# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
import json
import time
import glob

__version__ = "1.0.0"

class InvalidCLFormat(Exception):
    pass

def generate_cl_filename():
    return 'C_CONTROL_LOG_' + time.strftime("%Y%m%d%H%M%S", time.localtime()) + '.txt'

def main():
    if len(sys.argv) <= 1:
        sys.exit("Usage: %s control_log_file [...]" % sys.argv[0])

    consolidated_control_logs = []

    for arg in sys.argv[1:]:
        for cl_file in glob.glob(arg):
            with open(cl_file, 'r') as f:
                print("Processing %s" % cl_file)
                try:
                    j = json.load(f)
                    control_logs = j['controlLogs']
                    if not isinstance(control_logs, list):
                        raise InvalidCLFormat("controlLogs is not a list")
                    for control_log in control_logs:
                        if not 'version' in control_log:
                            raise InvalidCLFormat("Version is not found")
                        consolidated_control_logs.append(control_log)
                except (json.decoder.JSONDecodeError, KeyError, InvalidCLFormat) as e:
                    sys.exit("Invalid control log file: %s" % cl_file)

    if len(consolidated_control_logs) == 0:
        sys.exit("No control logs processed")

    cl_path = generate_cl_filename()
    with open(cl_path, 'w') as f:
        json.dump({"controlLogs" : consolidated_control_logs}, f, indent=2)

    print(cl_path)

if __name__ == "__main__":
    main()

