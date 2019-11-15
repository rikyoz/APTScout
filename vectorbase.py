#!/usr/bin/python3
import argparse
import errno
import json
import math
import os
import sys


if sys.version_info[0] < 3:
    math.log2 = lambda x: (math.log(x) / math.log(2))


def size_type(x):
    x = int(x)
    if x < 64:
        raise argparse.ArgumentTypeError("Minimum vector size is 64")
    if x & (x - 1) != 0:  # if x is not a power of 2
        raise argparse.ArgumentTypeError("Vector size must be a power of 2")
    return x


def normalize(api):
    dll_name, api_name = api.split("!")
    if dll_name.startswith("msvcr"):
        dll_name = "msvcrt.dll"
    if api_name.endswith("W") or api_name.endswith("A"):
        api_name = api_name[:-1]
    return "{}!{}".format(dll_name, api_name)


def entropy(p):
    q = 1 - p
    return -(p*math.log2(p) + q*math.log2(q))


def main(args, occurrences_csv, dataset_json):
    api_categories = {}
    with open(args.api_csv, mode="r") as fp:
        for line in fp:
            api = line.split(",")
            key = normalize(api[2].strip())
            if key not in api_categories:
                api_categories[key] = api[:2]

    exec_count = 1
    with open(dataset_json, mode="r") as fp:
        exec_count = json.load(fp)["samples"]["total"]

    vector_base = []
    with open(occurrences_csv, mode="r") as fp:
        next(fp)
        for index, line in enumerate(fp):
            if index >= args.size:  # stops at maximum vector base size
                break
            api, occurrences = line.split(";")
            api = normalize(api.strip())

            weight = 1
            if args.weights == "linear":
                weight = index
            elif args.weights == "nonlinear":
                n = args.size
                weight = round(50 * (1 + math.tanh(3 * (2 * index - n) / (2 * n))))
            elif args.weights == "entropy":
                n = args.size
                p = int(occurrences.strip()) / exec_count
                weight = round((entropy(p) * (n - 1)) + 1)

            if api in api_categories:
                cat = api_categories[api]
            else:
                cat = ["unknown", "TODO"]
            vector_base.append("{};{};{};{}".format(cat[0], cat[1], api, weight))

    if len(vector_base) < args.size:
        print("Padding of {} elements required!".format(args.size - len(vector_base)))
    vector_base = sorted(vector_base)
    while len(vector_base) < args.size:
        vector_base.append("padding;padding;padding!padding;0".format())

    with open(args.out_file, mode="w") as fp:
        for index, base_api in enumerate(vector_base):
            fp.write("{}\n".format(base_api))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculates an ApiVectorBase based on dataset statistics")
    parser.add_argument("data_dir", help="Data directory containing the CSV file with the API occurrences")
    parser.add_argument("-i", "--imports_type", dest="imports_type", choices=['all', 'it', 'dynamic'],
                        default="all", help="Type of imports to be considered for creating the ApiVectorBase")
    parser.add_argument("-a", "--api_csv", dest="api_csv", default="./apiscout/apiscout/data/winapi_contexts.csv",
                        help="CSV file containing apiscout's categorized API list")
    parser.add_argument("-w", "--weights", dest="weights", choices=["equal", "linear", "nonlinear", "entropy"],
                        default="linear", help="Type of weights to be used for vectors comparison")
    parser.add_argument("-s", "--size", dest="size", type=size_type, default=4096,
                        help="Size of the output ApiVectorBase (must be a power of 2 and >= 64)")
    parser.add_argument("-o", "--out_file", dest="out_file", default=None,
                        help="Output CSV file which will contain the ApiVectorBase desired")
    args = parser.parse_args()

    if not os.path.isdir(args.data_dir):
        print("Data directory '{}' does not exist!".format(args.data_dir))
        sys.exit(1)

    occurrences_csv = os.path.join(args.data_dir, "{}.csv".format(args.imports_type))
    if not os.path.isfile(occurrences_csv):
        print("Occurrences CSV file '{}' does not exist!".format(occurrences_csv))
        sys.exit(1)

    dataset_json = os.path.join(args.data_dir, "dataset.json")
    if not os.path.isfile(dataset_json):
        print("Dataset JSON file '{}' does not exist".format(dataset_json))
        sys.exit(1)

    if not os.path.isfile(args.api_csv):
        print("Api Contexts CSV file '{}' does not exist!".format(args.api_csv))
        sys.exit(1)

    if args.out_file is None:
        filename = "vectorbase_{}_{}_{}.csv".format(args.imports_type, args.weights, args.size)
        args.out_file = os.path.join(args.data_dir, "bases", filename)
    if not os.path.exists(os.path.dirname(args.out_file)):
        try:
            os.makedirs(os.path.dirname(args.out_file))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    main(args, occurrences_csv, dataset_json)
