#!/usr/bin/python3
import argparse
import errno
import json
import logging
import math
import multiprocessing
import os
import sys
import time
import warnings
from apiscout.ApiVector import ApiVector
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from itertools import combinations, groupby, repeat
from multiprocessing import Pool
from tqdm import tqdm


def thread_type(x):
    x = int(x)
    if x == 0:
        raise argparse.ArgumentTypeError("Minimum thread number is 1")
    if x % 2 != 0:  # if x is not a multiple of 2
        raise argparse.ArgumentTypeError("Thread number must be a multiple of 2")
    max_threads = multiprocessing.cpu_count()
    if x > max_threads:
        raise argparse.ArgumentTypeError("Maximum thread number available on the system is {}".format(max_threads))
    return x


def split_jobs(job_list, wanted_parts=1):
    length = len(job_list)
    return [job_list[i*length // wanted_parts: (i+1)*length // wanted_parts] for i in range(wanted_parts)]


def worker_function(worker_id, api_vector, jobs, vectors, verbose):
    # print("[thread {}] args: {}, {}, {}, {}".format(thread_id, api_vector, len(jobs), id(vectors), verbose))
    try:
        # count = 0
        # total = len(jobs)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            text = "worker #{:02d}: ".format(worker_id)
            scores = defaultdict(dict)
            for sample1, sample2 in tqdm(jobs, position=worker_id, desc=text, unit=" scores"):
                score = api_vector.matchVectors(vectors[sample1], vectors[sample2])
                scores[sample1][sample2] = score if not math.isnan(score) else 0.0
                scores[sample2][sample1] = scores[sample1][sample2]
                # logging.info("[worker {:02d}] job progress: {:.2f}%".format(worker_id, 100.0 * (count / total)))
            return scores
    except Exception as ex:
        print(str(ex))


def merge_dictionaries(dictionaries):
    result = defaultdict(dict)
    for d in dictionaries:
        for k, v in d.items():
            # Note: dictionary keys in v should not overlap the ones already in result[k]
            #       since we used itertools.combinations
            result[k].update(v)
    result = OrderedDict(sorted(result.items()))
    for k, v in result.items():
        result[k] = OrderedDict(sorted(v.items()))
    return result


def main(args):
    with open(args.vectors_file, mode="r") as fp:
        vectors_file = json.load(fp)

        vectors = vectors_file["vectors"]
        vectors_dir = os.path.dirname(args.vectors_file)

        jobs_list = list(combinations(vectors.keys(), 2))
        splitted_jobs = split_jobs(jobs_list, args.threads)
        logging.debug("Jobs count: {}".format(len(jobs_list)))
        logging.debug("  For each worker: {}".format([len(splitted) for splitted in splitted_jobs]))

        vectorbase_path = os.path.normpath(os.path.join(vectors_dir, vectors_file["base"]["path"]))
        if not os.path.isfile(vectorbase_path):
            logging.error("VectorBase file '{}' does not exist".format(vectorbase_path))
            sys.exit(1)

        scores = {}
        with Pool(args.threads) as pool:
            api_vector = ApiVector(vectorbase_path)
            results = []
            for i in range(args.threads):
                task_args = (i, api_vector, splitted_jobs[i], vectors, args.verbose)
                results.append(pool.apply_async(worker_function, args=task_args))
            pool.close()
            pool.join()
            logging.info("Merging the results... ")
            scores = merge_dictionaries([res.get() for res in results])
            logging.info("  COMPLETED")

        out_dir = os.path.join(os.path.dirname(vectors_dir), "scores")
        base = vectors_file["base"]
        if args.out_file is None:
            args.out_file = os.path.join(out_dir, "scores_{}_{}_{}.json".format(base["imports_type"],
                                                                                base["weights"],
                                                                                base["size"]))
        if not os.path.exists(os.path.dirname(args.out_file)):
            try:
                os.makedirs(os.path.dirname(args.out_file))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        dataset_path = os.path.normpath(os.path.join(vectors_dir, vectors_file["dataset"]))
        scores_dict = {
            "dataset": os.path.relpath(dataset_path, out_dir),
            "base": vectors_file["base"],
            "scores": scores
        }
        scores_dict["base"]["path"] = os.path.relpath(vectorbase_path, out_dir)

        with open(args.out_file, mode="w") as opf:
            logging.info("Dumping scores to '{}'... ".format(os.path.basename(args.out_file)))
            json.dump(scores_dict, opf, indent=4)
            logging.info("  COMPLETED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Matches ApiVectors against each other to calculate similarity scores")
    parser.add_argument("vectors_file",
                        help="JSON file containing all the ApiVectors to be analyzed")
    parser.add_argument("-t", "--threads", default=multiprocessing.cpu_count(), type=thread_type,
                        help="Number of threads to use for calculating the scores")
    parser.add_argument("-o", "--out_file", default=None,
                        help="The output JSON file which will contain the scores")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show verbose output")
    arguments = parser.parse_args()

    if not os.path.isfile(arguments.vectors_file):
        print("Vectors file '{}' does not exist".format(arguments.vectors_file))
        sys.exit(1)

    logging.basicConfig(format="%(message)s", level=logging.INFO if arguments.verbose else logging.WARNING)

    main(arguments)
