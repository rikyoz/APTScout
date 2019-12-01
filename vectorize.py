#!/usr/bin/python3
import argparse
import errno
import json
import os
import re
import sys
from apiscout.ApiVector import ApiVector
from collections import defaultdict
from numpy import median


class decoder(json.JSONDecoder):
    def __init__(self, list_type=list,  **kwargs):
        json.JSONDecoder.__init__(self, **kwargs)
        # Use the custom JSONArray
        self.parse_array = self.JSONArray
        # Use the python implemenation of the scanner
        self.scan_once = json.scanner.py_make_scanner(self)
        self.list_type = list_type

    def JSONArray(self, s_and_end, scan_once, **kwargs):
        values, end = json.decoder.JSONArray(s_and_end, scan_once, **kwargs)
        return self.list_type(values), end


def merge_two_dicts(x, y):
    res = defaultdict(set)
    for k, v in x.items():
        res[k].update(v)
    for k, v in y.items():
        res[k].update(v)
    # res[k] = list(res[k])
    return dict(res)


def detect_weights(base_name, base_list):
    match = re.search("_(linear|nonlinear|equal|entropy)_", base_name)
    if match:
        return match.group(1)
    # user changed the vectorbase filename, so we must try to determine the weights type from their values
    for api in reversed(base_list):
        if api[0] != "padding":
            if api[3] == 0:
                return "linear"
            elif api[3] == base_list[0][3] and api[3] == 1:
                return "equal"
            elif api[3] == 5:
                return "nonlinear"
            else:
                return "entropy"


def unix_relpath(path, start):
    rel_path = os.path.relpath(path, start)
    if os.name == "nt":
        # On Windows, relpath normalized the path and changed all / into \\
        # However, we want use unix path separator when writing a path inside a file,
        # since they are supported everywhere (also on Windows)!
        rel_path = "/".join(rel_path.split("\\"))
    return rel_path


def vectorize(dataset, logs_folder, base, imports_type, data_dir, dataset_file=None, out_file=None):
    api_vector = ApiVector(base)
    vector_base = api_vector.getWinApi1024()
    vector_weights = detect_weights(os.path.basename(base), vector_base)
    vector_size = len(vector_base)

    if out_file is None:
        out_path = os.path.join(data_dir, "vectors")
    else:
        out_path = os.path.dirname(out_file)

    if not os.path.exists(out_path):
        try:
            os.makedirs(out_path)
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    if out_file is None:
        out_file = os.path.join(out_path, "vectors_{}_{}_{}.json".format(imports_type, vector_weights, vector_size))

    vectors_dict = {
        "dataset": unix_relpath(dataset_file, out_path) if dataset_file is not None else None,
        "base": {
            "path": unix_relpath(base, out_path),
            "imports_type": imports_type,
            "weights": vector_weights,
            "size": vector_size
        },
        "vectors": {},
        "coverage": {
            "average": 0,
            "median": 0,
            "details": {}
        }
    }
    for sample in dataset:
        sample_log_path = os.path.join(logs_folder, "{}.json".format(sample))
        with open(sample_log_path, mode="r") as log_file:
            apis = json.load(log_file, cls=decoder, list_type=set)

            if imports_type == "all":
                apis = merge_two_dicts(apis["it"], apis["dynamic"])
            else:
                apis = apis[imports_type]

            result = api_vector.getApiVectorFromApiDictionary(apis)["user_list"]
            coverage = result["percentage"]
            vectors_dict["vectors"][sample] = result["vector"]
            vectors_dict["coverage"]["details"][sample] = coverage
            vectors_dict["coverage"]["average"] += coverage
    vectors_dict["coverage"]["average"] /= len(vectors_dict["coverage"]["details"])
    vectors_dict["coverage"]["median"] = median(list(vectors_dict["coverage"]["details"].values()))

    with open(out_file, mode="w") as vectors_file:
        json.dump(vectors_dict, vectors_file, indent=4)


def main(dataset_file, logs_folder, base, imports_type, data_dir, out_file=None):
    with open(dataset_file, mode="r") as dfp:
        dataset = json.load(dfp)["samples"]["classification"]
        vectorize(dataset, logs_folder, base, imports_type, data_dir, dataset_file, out_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculates the ApiVectors of crawled binaries")
    parser.add_argument("logs_folder",
                        help="Folder containing the JSON logs generated by ghidra_scripts/aptscout.py")
    parser.add_argument("data_dir",
                        help="Data directory containing the dataset.json file")
    parser.add_argument("-i", "--imports_type", choices=['all', 'it', 'dynamic'], default="all",
                        help="Type of imports to be vectorized")
    parser.add_argument("-b", "--base", default=None,
                        help="File containing the ApiVectorBase to be used")
    parser.add_argument("-o", "--out_file", default=None,
                        help="Output JSON file which will contain the vectors of the analyzed binaries")
    args = parser.parse_args()

    if not os.path.isdir(args.logs_folder):
        print("Log folder '{}' does not exist!".format(args.logs_folder))
        sys.exit(1)

    if not os.path.isdir(args.data_dir):
        print("Data directory '{}' does not exist!".format(args.data_dir))
        sys.exit(1)

    dataset_file = os.path.join(args.data_dir, "dataset.json")
    if not os.path.isfile(dataset_file):
        print("Data directory '{}' does not contain a dataset.json file!".format(args.data_dir))
        sys.exit(1)

    if args.base is None:
        args.base = os.path.join(args.data_dir, "bases", "vectorbase_{}_linear_4096.csv".format(args.imports_type))
    elif os.path.isfile(os.path.join(args.data_dir, "bases", args.base)):
        args.base = os.path.join(args.data_dir, "bases", args.base)

    if not os.path.isfile(args.base):
        print("VectorBase file '{}' does not exist".format(args.base))
        sys.exit(1)

    main(dataset_file, **vars(args))
