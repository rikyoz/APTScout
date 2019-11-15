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


def main(args, dataset_path):
    with open(dataset_path, mode="r") as dataset_file:
        dataset_classification = json.load(dataset_file)["samples"]["classification"]

        api_vector = ApiVector(args.base)
        base = api_vector.getWinApi1024()
        base_weights = detect_weights(os.path.basename(args.base), base)
        vector_size = len(base)

        if args.out_file is None:
            out_path = os.path.join(args.data_dir, "vectors")
        else:
            out_path = os.path.dirname(args.out_file)

        if not os.path.exists(out_path):
            try:
                os.makedirs(out_path)
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        if args.out_file is None:
            args.out_file = os.path.join(out_path,
                                         "vectors_{}_{}_{}.json".format(args.imports_type, base_weights, vector_size))

        vectors_dict = {
            "dataset": os.path.relpath(dataset_path, out_path),
            "base": {
                "path": os.path.relpath(args.base, out_path),
                "imports_type": args.imports_type,
                "weights": base_weights,
                "size": vector_size
            },
            "vectors": {},
            "coverage": {
                "average": 0,
                "median": 0,
                "details": {}
            }
        }
        for sample, apt in dataset_classification.items():
            sample_log_path = os.path.join(args.log_folder, "{}.json".format(sample))
            with open(sample_log_path, mode="r") as log_file:
                apis = json.load(log_file, cls=decoder, list_type=set)

                if args.imports_type == "all":
                    apis = merge_two_dicts(apis["it"], apis["dynamic"])
                else:
                    apis = apis[args.imports_type]

                result = api_vector.getApiVectorFromApiDictionary(apis)["user_list"]
                coverage = result["percentage"]
                vectors_dict["vectors"][sample] = result["vector"]
                vectors_dict["coverage"]["details"][sample] = coverage
                vectors_dict["coverage"]["average"] += coverage
        vectors_dict["coverage"]["average"] /= len(vectors_dict["coverage"]["details"])
        vectors_dict["coverage"]["median"] = median(list(vectors_dict["coverage"]["details"].values()))

        with open(args.out_file, mode="w") as vectors_file:
            json.dump(vectors_dict, vectors_file, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculates the ApiVectors of crawled binaries")
    parser.add_argument("log_folder", help="Folder containing the json logs of ghidra_scout.py")
    parser.add_argument("data_dir", help="Data directory containing the dataset.json file")
    parser.add_argument("-i", "--imports_type", dest="imports_type", choices=['all', 'it', 'dynamic'],
                        default="all", help="Type of imports to be vectorized")
    parser.add_argument("-b", "--base", dest="base", default=None,
                        help="File containing the ApiVectorBase to be used")
    parser.add_argument("-o", "--out_file", dest="out_file", default=None,
                        help="Output JSON file which will contain the vectors of the analyzed binaries")
    args = parser.parse_args()

    if not os.path.isdir(args.log_folder):
        print("Log folder '{}' does not exist!".format(args.log_folder))
        sys.exit(1)

    if not os.path.isdir(args.data_dir):
        print("Data directory '{}' does not exist!".format(args.data_dir))
        sys.exit(1)

    dataset_path = os.path.join(args.data_dir, "dataset.json")
    if not os.path.isfile(dataset_path):
        print("Data directory '{}' does not contain a dataset.json file!".format(args.data_dir))
        sys.exit(1)

    if args.base is None:
        args.base = os.path.join(args.data_dir, "bases", "vectorbase_{}_linear_4096.csv".format(args.imports_type))
    elif os.path.isfile(os.path.join(args.data_dir, "bases", args.base)):
        args.base = os.path.join(args.data_dir, "bases", args.base)

    if not os.path.isfile(args.base):
        print("VectorBase file '{}' does not exist".format(args.base))
        sys.exit(1)

    main(args, dataset_path)
