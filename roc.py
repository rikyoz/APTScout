#!/usr/bin/python3
import argparse
import fnmatch
import json
import logging
import matplotlib.pyplot as plt
import numpy as np
import os
import random
import sys
from collections import defaultdict
from matplotlib.ticker import AutoMinorLocator
from sklearn.metrics import roc_curve, auc
from tqdm import tqdm


def size_type(x):
    x = int(x)
    if x < 64:
        raise argparse.ArgumentTypeError("Minimum vector size is 64")
    if x & (x - 1) != 0:  # if x is not a power of 2
        raise argparse.ArgumentTypeError("Vector size must be a power of 2")
    return x


def calculate_roc_curve(scores, classes):
    y_similarity_true = []
    y_similarity_scores = []
    matched_samples = defaultdict(set)
    for sample, data in scores.items():
        true_class = classes[sample]
        for other_sample, score in data.items():
            other_class = classes[other_sample]
            if other_sample not in matched_samples[sample] and sample not in matched_samples[other_sample]:
                y_similarity_true.append(1 if true_class == other_class else 0)
                y_similarity_scores.append(score)
                matched_samples[sample].add(other_sample)
                matched_samples[other_sample].add(sample)

    fpr, tpr, _ = roc_curve(y_similarity_true, y_similarity_scores, pos_label=1)
    return fpr, tpr


def plot_roc(roc_dict, out_file):
    fig, ax = plt.subplots()
    dpi = fig.get_dpi()
    fig.set_size_inches(800.0 / float(dpi), 800.0 / float(dpi))
    ax.xaxis.set_minor_locator(AutoMinorLocator(5))
    ax.yaxis.set_minor_locator(AutoMinorLocator(5))
    ax.grid(True, which="major", alpha=0.75, linestyle='dashed')
    ax.grid(True, which="minor", alpha=0.25, linestyle='dashed')
    line_width = 1.5
    # cmap = plt.get_cmap('tab10')
    colors = ["steelblue", "darkorange", "red", "forestgreen", "dodgerblue", "darkviolet", "saddlebrown", "teal",
              "olivedrab", "deeppink", "royalblue", "darkgoldenrod", "mediumseagreen", "mediumslateblue"]
    for index, (label, (fpr, tpr)) in enumerate(sorted(roc_dict.items(), key=lambda k: k[0])):
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, color=colors[(index + 1) % len(colors)],
                 lw=line_width, label="{} (area = {:.4f})".format("-".join(str(l) for l in label), roc_auc))
    plt.plot([0, 1], [0, 1], color=colors[0], lw=line_width, linestyle="--", label="Random guess")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.0])
    plt.xticks(np.arange(0, 1.1, 0.1))
    plt.yticks(np.arange(0, 1.1, 0.1))
    plt.xlabel('False Positive Rate (1 - specificity)')
    plt.ylabel('True Positive Rate (sensitivity)')
    plt.title("Receiver Operating Characteristic")
    plt.legend(loc="lower right")
    plt.tight_layout()
    fig.savefig(out_file)


def main(scores_folder, imports_types, weights, sizes, display, out_dir, verbose):
    # logging.info("Calculating ROC curves...")
    text = "Calculating ROC curves... "
    roc_dict = {}
    for filename in tqdm(os.listdir(scores_folder), desc=text, unit="roc"):
        with open(os.path.join(scores_folder, filename), mode="r") as scores_file:
            scores_dict = json.load(scores_file)
            base = scores_dict["base"]
            if imports_types is not None and base["imports_type"] not in imports_types:
                continue
            if weights is not None and base["weights"] not in weights:
                continue
            if sizes is not None and base["size"] not in sizes:
                continue

            dataset_path = os.path.normpath(os.path.join(scores_folder, scores_dict["dataset"]))
            if not os.path.isfile(dataset_path):
                print("Dataset file '{}' of scores file '{}' does not exist".format(dataset_path, filename))
                sys.exit(1)

            with open(dataset_path, mode="r") as dfp:
                classes = json.load(dfp)["samples"]["classification"]
                base = tuple(scores_dict["base"].values())[1:]
                roc_dict[base] = calculate_roc_curve(scores_dict["scores"], classes)

    if len(roc_dict) > 0:
        suffixes = []
        if imports_types is not None:
            suffixes.append("-".join(imports_types))
        if weights is not None:
            suffixes.append("-".join(weights))
        if sizes is not None:
            suffixes.append("-".join(str(s) for s in sizes))
        roc_path = os.path.join(out_dir, "{}.svgz".format("_".join(["roc"] + suffixes)))

        logging.info("Plotting the results to '{}'... ".format(os.path.basename(roc_path)))
        plot_roc(roc_dict, roc_path)
        logging.info("  COMPLETED")

        if display:
            plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plots a ROC curve from ApiVectors similarity scores")
    parser.add_argument("scores_folder",
                        help="Directory contianing the JSON files with the scores to be plotted")
    parser.add_argument("-i", "--imports_types", nargs="+", choices=['all', 'it', 'dynamic'],
                        help="Plot only scores calculated from vectors built from the specified types of imports")
    parser.add_argument("-w", "--weights", nargs="+", choices=["equal", "linear", "nonlinear", "entropy"],
                        help="Plot only scores calculated using the specified types of weights")
    parser.add_argument("-s", "--sizes", nargs="+", type=size_type,
                        help="Plot only scores calculated from vectors with the specified sizes")
    parser.add_argument("-d", "--display", action="store_true",
                        help="Specify if the final plot must be shown to the user")
    parser.add_argument("-o", "--out_dir",
                        help="Output directory going to contain the plots images")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show verbose output")
    args = parser.parse_args()

    logging.basicConfig(format="%(message)s", level=logging.INFO if args.verbose else logging.WARNING)

    if not os.path.isdir(args.scores_folder):
        logging.error("Scores folder '{}' does not exist!".format(args.scores_folder))
        sys.exit(1)

    if args.out_dir is None:
        args.out_dir = os.path.join(os.path.dirname(os.path.normpath(args.scores_folder)), "plots")
    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)
    elif not os.path.isdir(args.out_dir):
        print("Invalid output dir '{}'".format(args.out_dir))
        sys.exit(1)

    main(**vars(args))
