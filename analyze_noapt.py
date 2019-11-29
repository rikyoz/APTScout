#!/usr/bin/python3
import argparse
import os
import shutil
import subprocess
import sys
from vectorize import vectorize


def run_command(cmd, args=[]):
    process = subprocess.Popen([cmd] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in iter(process.stdout.readline, ''):
        print(line, end="")
    process.stdout.close()
    return_code = process.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)


def run_ghidra(cmd, args):
    if os.name == 'nt':
        # On Windows, analyzeHeadless does not exit if it is called directly (i.e. outside cmd.exe, like when using
        # shell=False of Popen) or with cmd.exe /c option (which is the default when using shell=True of Popen).
        # To avoid this, we use cmd.exe /k option and call exit() after analyzeHeadless finishes.
        run_command("cmd.exe", ["/k", cmd] + args + ["&", "exit()"])
    else:
        run_command(cmd, args)


def main(command, project_dir, project_name, import_samples, analyze, base_path, imports_type):
    if import_samples is not None:
        run_ghidra(command, [project_dir, project_name, "-import", import_samples])

    logs_path = os.path.join(sys.path[0], "apilogs_nonapt")
    data_path = os.path.join(sys.path[0], "data", "normalized_nonapt")
    if analyze:
        scripts_path = os.path.join(sys.path[0], "ghidra_scripts")
        apidb_path = os.path.join(sys.path[0], "data", "apidb.json")
        run_ghidra(command, [project_dir, project_name, "-process", "-noanalysis", "-readOnly",
                   "-scriptPath", scripts_path,
                   "-postScript", "aptscout.py", "all", "/v", "/log", logs_path, "/apidb", apidb_path])

    if base_path is not None and os.path.isdir(logs_path):
        dataset = [sample.replace(".json", "") for sample in os.listdir(logs_path)]
        vectorize(dataset, logs_path, base_path, imports_type, data_path)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch analyzes executables using Ghidra")
    parser.add_argument("project_dir",
                        help="Directory containing the Ghidra project to analyze")
    parser.add_argument("project_name",
                        help="Name of the project to analyze")
    parser.add_argument("-i", "--import_samples",
                        help="Makes Ghidra import and analyze the binaries in the specified directory")
    parser.add_argument("-a", "--analyze", action="store_true",
                        help="Batch analyzes the APIs used by the executables in the input project using APTScout")
    parser.add_argument("-v", "--vectorize", dest="base_path",
                        help="Vectorize the obtained API logs using the specified ApiVectorBase file")
    parser.add_argument("-t", "--type", dest="imports_type", choices=['all', 'it', 'dynamic'], default="all",
                        help="Type of imports to be vectorized")
    args = parser.parse_args()

    if not os.path.isdir(args.project_dir):
        print("Project's directory '{}' does not exist".format(args.project_dir))
        sys.exit(1)
    args.project_dir = os.path.normpath(args.project_dir)

    if args.import_samples is not None:
        args.import_samples = os.path.normpath(args.import_samples)

    if args.base_path is not None:
        if not os.path.isfile(args.base_path):
            print("ApiVectorBase file '{}' does not exist".format(args.base_path))
            sys.exit(1)
        else:
            args.base_path = os.path.normpath(args.base_path)

    for command in ["analyzeHeadless.bat", "ghidra"]:
        if shutil.which(command) is not None:
            sys.exit(main(command, **vars(args)))
    print("Ghidra's headless analyzer command was not found!")
    sys.exit(1)
