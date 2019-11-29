#!/usr/bin/python3
import argparse
import csv
import json
import math
import matplotlib.pyplot as plt
import numpy as np
import os
import sys
from collections import Counter, defaultdict, OrderedDict
from matplotlib.ticker import AutoMinorLocator


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


class encoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


class OrderedCounter(Counter, OrderedDict):
    pass


def merge_two_dicts(x, y):
    res = defaultdict(set)
    for k, v in x.items():
        res[k].update(v)
    for k, v in y.items():
        res[k].update(v)
    return dict(res)


nonc_keys = [
    "microsoft visual basic v5.0",
    "microsoft visual basic v5.0 - v6.0",
    "microsoft visual c# / basic .net",
    "microsoft visual c# v7.0 / basic .net",
    "borland delphi 4.0",
    "borland delphi v3.0",
    "borland delphi v6.0 - v7.0",
    "bobsoft mini delphi -> bob / bobsoft"
]


packed_keys = [
    "upx v0.80 - v0.84",
    "upx v3.0 (exe_lzma) -> markus oberhumer & laszlo molnar & john reiser",
    "upx 2.90 (lzma)",
    "upx -> www.upx.sourceforge.net",
    "upx v0.89.6 - v1.02 / v1.05 - v1.22",
    "upx 2.93 (lzma)",
    "pecompact 2.5x -> jeremy collake",
    "pecompact 2.0x heuristic mode -> jeremy collake",
    "pecompact 2.x -> jeremy collake",
    "pecompact v2.0",
    "rar sfx",
    "nullsoft pimp stub -> sfx",
    "microsoft cab sfx",
    "pespin v1.3 -> cyberbob (h)",
    "pespin v1.304 -> cyberbob&nbsp; &nbsp;* sign.by.fly * 20080310",
    "pespin 1.3beta -> cyberbob (h)",
    "pespin v1.304 -> cyberbob",
    "pespin v0.1 -> cyberbob (h)",
    "other_packer"
]


def is_any_of(keys, row):
    for key in keys:
        if row[key] == "1":
            return True
    return False


def count_apis(log):
    count = 0
    for _, apis in log.items():
        count += len(apis)
    return count


def count_api_references(dll, apis, api_counters, apt, api_type, normalize):
    if normalize:
        for api in apis.copy():
            if api.endswith("W") or api.endswith("A"):
                apis.discard(api)
                apis.add(api[:-1])
    for api in apis:
        api_counters[api_type]["{}!{}".format(dll, api)] += 1
        api_counters["per_apt"][apt][api_type]["{}!{}".format(dll, api)] += 1


def api_log_stats(log, api_type, api_counters, apt, normalize):
    count = 0
    dll_list = []
    for dll, apis in log[api_type].items():
        if normalize:
            if dll.startswith("msvcr"):
                dll = "msvcrt.dll"
            for api in apis.copy():
                if api.endswith("W") or api.endswith("A"):
                    apis.discard(api)
                    apis.add(api[:-1])

        dll_list.append(dll)
        count += len(apis)

        for api in apis:
            formatted_api = "{}!{}".format(dll, api)
            api_counters[api_type][formatted_api] += 1
            api_counters["per_apt"][apt][api_type][formatted_api] += 1

    return dll_list, count


def write_stats_csv(out_dir, api_counters, import_type, apt=""):
    if apt:
        apt = apt.replace(" ", "_") + "_"
    with open(os.path.join(out_dir, "{}{}.csv".format(apt, import_type)), mode="w") as stats_file:
        stats_file.write("api; occurrences\n")
        for dll_api, count in api_counters[import_type].most_common():
            stats_file.write("{}; {}\n".format(dll_api, count))


def plot_distribution(occurrences, ylabel, xlabel, out_file, most_common=True, show_x_ticks=False):
    if most_common:
        x, y = zip(*occurrences.most_common())
    else:
        x, y = zip(*sorted(occurrences.items()))
    fig, ax = plt.subplots()
    dpi = fig.get_dpi()
    fig.set_size_inches(900.0 / float(dpi), 800.0 / float(dpi))
    ax.plot(x, y, color="dodgerblue", lw=1.5)
    ax.fill_between(x, 0, y, alpha=.3)
    # plt.margins(0, 0)
    ax.set(ylim=(0, plt.yticks()[0][-1]))
    if not show_x_ticks:
        ax.set(xlim=(0, None))
        plt.xticks([])
    else:
        ax.set(xlim=(0, plt.xticks()[0][-1]))
        plt.xticks(list(plt.xticks()[0]).append(ax.get_xlim()[1]))
        ax.xaxis.set_minor_locator(AutoMinorLocator(5))
        ax.yaxis.set_minor_locator(AutoMinorLocator(5))
        ax.grid(True, which="major", linestyle='dashed')
        ax.grid(True, which="minor", alpha=0.5, linestyle='dashed')
    plt.ylabel(ylabel)
    plt.xlabel(xlabel)
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close()


def main(args):
    dataset = {}
    dataset_stats = {
        "samples": {
            "total": 0,
            "dotnet": 0,
            "nonc": 0,
            "dlls": 0,
            "packed": 0,
            "empty": 0,
            "per_apt": defaultdict(int),
            "classification": {}
        },
        "apts": {
            "total": 0,
            "avg_samples": 0
        },
        "apis": {
            "all": 0,
            "it": 0,
            "dynamic": 0,
            "per_sample": {"all": 0, "it": 0, "dynamic": 0},
            "per_apt": defaultdict(lambda: {"all": 0, "it": 0, "dynamic": 0}),
            "dist": {
                "all": OrderedCounter(),
                "it": OrderedCounter(),
                "dynamic": OrderedCounter()
            }
        },
        "dlls": {
            "all": {
                "count": 0,
                "list": set()
            },
            "it": {
                "count": 0,
                "list": set()
            },
            "dynamic": {
                "count": 0,
                "list": set()
            },
            "per_apt": {}
        }
    }
    api_counters = {
        "it": Counter(),
        "dynamic": Counter(),
        "all": Counter(),
        "per_apt": defaultdict(lambda: {"it": Counter(), "dynamic": Counter(), "all": Counter()})
    }
    dll_counters = {
        "it": Counter(),
        "dynamic": Counter(),
        "all": Counter(),
        "per_apt": defaultdict(lambda: {"it": Counter(), "dynamic": Counter(), "all": Counter()})
    }
    with open(args.dataset, mode="r") as dataset_file:
        csv_reader = csv.DictReader(dataset_file, delimiter=',')
        for row in csv_reader:
            apt = row["apt"]
            log_path = os.path.join(args.log_folder, "{}.json".format(row["md5"]))
            if not os.path.exists(log_path):
                continue
            if "dll" in args.ignore and row["dll"] == "True":
                continue
            if "dotnet" in args.ignore and row[".net executable"] == "1":
                continue
            if "nonc" in args.ignore and is_any_of(nonc_keys, row):
                continue
            if "packed" in args.ignore and is_any_of(packed_keys, row):
                continue

            with open(log_path) as api_log_file:
                api_log = json.load(api_log_file, cls=decoder, list_type=set)
                api_log["all"] = merge_two_dicts(api_log["it"], api_log["dynamic"])
                if "empty" in args.ignore and len(api_log["all"]) == 0:
                    continue
                if len(api_log["all"]) == 0:
                    dataset_stats["samples"]["empty"] += 1
                if args.min_apis > 0 and count_apis(api_log["all"]) < args.min_apis:
                    continue

                for import_type in ["it", "dynamic", "all"]:
                    dll_list, api_count = api_log_stats(api_log, import_type, api_counters, apt, args.normalize)
                    dataset_stats["dlls"][import_type]["list"].update(dll_list)
                    dataset_stats["apis"]["dist"][import_type][api_count] += 1

            if row["dll"] == "True":
                dataset_stats["samples"]["dlls"] += 1
            if row[".net executable"] == "1":
                dataset_stats["samples"]["dotnet"] += 1
            if is_any_of(nonc_keys, row):
                dataset_stats["samples"]["nonc"] += 1
            if is_any_of(packed_keys, row):
                dataset_stats["samples"]["packed"] += 1

            dataset_stats["samples"]["total"] += 1
            dataset_stats["samples"]["per_apt"][apt] += 1
            dataset_stats["samples"]["classification"][row["md5"]] = apt
            dataset[row["md5"]] = apt

        dataset_stats["apts"]["total"] = len(dataset_stats["samples"]["per_apt"])
        dataset_stats["apts"]["avg_samples"] = dataset_stats["samples"]["total"] / dataset_stats["apts"]["total"]

    if args.apt_stats:
        per_apt_path = os.path.join(args.out_dir, "per_apt")
        if not os.path.exists(per_apt_path):
            os.mkdir(per_apt_path)

    plots_dir = os.path.join(args.out_dir, "plots")
    if not os.path.exists(plots_dir):
        os.makedirs(plots_dir)

    for import_type in ["it", "dynamic", "all"]:
        dataset_stats["dlls"][import_type]["list"] = sorted(dataset_stats["dlls"][import_type]["list"])
        dataset_stats["dlls"][import_type]["count"] = len(dataset_stats["dlls"][import_type]["list"])
        dataset_stats["apis"]["dist"][import_type] = {k: v for k, v in
                                                      sorted(dataset_stats["apis"]["dist"][import_type].items())}
        dataset_stats["apis"][import_type] = len(api_counters[import_type])

        write_stats_csv(args.out_dir, api_counters, import_type)
        if args.apt_stats:
            for apt, counters in api_counters["per_apt"].items():
                write_stats_csv(per_apt_path, counters, import_type, apt)

        dist_svg = os.path.join(plots_dir, "api_dist_{}.svg".format(import_type))
        xlabel = "API function ({})".format("it + dynamic" if import_type == "all" else import_type)
        plot_distribution(api_counters[import_type], "Occurrence in dataset", xlabel, dist_svg)

        size_dist_svg = os.path.join(plots_dir, "size_dist_{}.svg".format(import_type))
        xlabel = "Number of entries ({})".format("it + dynamic" if import_type == "all" else import_type)
        plot_distribution(dataset_stats["apis"]["dist"][import_type], "Occurrence in dataset",
                          xlabel, size_dist_svg, False, True)

    dataset_path = os.path.join(args.out_dir, "dataset.json")
    with open(dataset_path, mode="w") as dataset_stats_file:
        json.dump(dataset_stats, dataset_stats_file, indent=4, cls=encoder)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculates some stats of crawled API by ghidra_scout.py")
    parser.add_argument("log_folder",
                        help="Folder containing the json logs of ghidra_scout.py")
    parser.add_argument("-o", "--out_dir", default=None,
                        help="Output directory going to contain the calculated stats")
    parser.add_argument("-d", "--dataset", default="./data/mixed_dataset.csv",
                        help="CSV file containing metadata about the crawled files")
    parser.add_argument("-i", "--ignore", nargs="+", default=[], choices=["dotnet", "nonc", "dll", "empty", "packed"],
                        help="Ignore executables with the specified features")
    parser.add_argument("-m", "--min_apis", type=int, default=0,
                        help="Ignore executables with less than the specified number of APIs")
    parser.add_argument("-n", "--normalize", action="store_true",
                        help="Normalize ANSI/Unicode APIs (e.g. drop W/A suffixes)")
    parser.add_argument("-p", "--plot", action="store_true",
                        help="Draw and save to file occurrence distributions plots")
    parser.add_argument("-a", "--apt_stats", action="store_true",
                        help="Calculate occurrences for each single apt")
    arguments = parser.parse_args()

    if not os.path.isfile(arguments.dataset):
        print("Dataset file '{}' does not exist!".format(arguments.dataset))
        sys.exit(1)

    if not os.path.isdir(arguments.log_folder):
        print("Log folder '{}' does not exist!".format(arguments.log_folder))
        sys.exit(1)

    if arguments.out_dir is None:
        if len(arguments.ignore) == 0 and arguments.min_apis == 0:
            folder_name = "all"
        else:
            ignored_list = arguments.ignore + ["min{}".format(arguments.min_apis)]
            folder_name = "_".join(["no{}".format(ign) for ign in ignored_list])
        arguments.out_dir = os.path.join("data",
                                         "normalized" if arguments.normalize else "raw",
                                         folder_name)
    if not os.path.exists(arguments.out_dir):
        os.makedirs(arguments.out_dir)
    elif not os.path.isdir(arguments.out_dir):
        print("Output directory '{}' is not a folder!".format(arguments.out_dir))
        sys.exit(1)

    main(arguments)
