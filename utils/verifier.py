#!/usr/bin/python
import argparse
import sys
import json
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verifies the correctness of crawled API by ghidra_scout.py")
    parser.add_argument("log_folder", help="Folder containing the json logs of ghidra_scout.py")
    parser.add_argument("api_db", help="The json file containing the db of WinAPIs")
    args = parser.parse_args()
    with open(args.api_db) as api_db_file:
        api_db = json.load(api_db_file)
        for filename in os.listdir(args.log_folder):
            with open(args.log_folder + "/" + filename) as api_log_file:
                api_log = json.load(api_log_file)
                for dll, apis in api_log["dynamic"].items():
                    for api in apis:
                        if api in api_db:
                            if dll not in api_db[api]:
                                print("Wrong DLL '{}' for API '{}' in file '{}'?".format(dll, api, filename))
                                print("    API can be found only in {}".format(api_db[api]))
                        else:
                            print("API '{}' not found in DB, not necessarily an error!".format(api))
