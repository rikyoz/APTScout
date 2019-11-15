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


colors = ["#1"]


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


def main(args):
    logging.info("Calculating ROC curves...")
    roc_dict = {}
    for filename in os.listdir(args.scores_folder):
        if not fnmatch.fnmatch(filename, args.filter):
            continue
        with open(os.path.join(args.scores_folder, filename), mode="r") as scores_file:
            scores_dict = json.load(scores_file)

            dataset_path = os.path.normpath(os.path.join(args.scores_folder, scores_dict["dataset"]))
            if not os.path.isfile(dataset_path):
                print("Dataset file '{}' of scores file '{}' does not exist".format(dataset_path, filename))
                sys.exit(1)

            with open(dataset_path, mode="r") as dfp:
                classes = json.load(dfp)["samples"]["classification"]
                base = tuple(scores_dict["base"].values())[1:]
                roc_dict[base] = calculate_roc_curve(scores_dict["scores"], classes)
    logging.info("  COMPLETED")

    if len(roc_dict) > 0:
        roc_path = os.path.join(args.out_dir, "roc.svg")
        logging.info("Plotting the results to '{}'... ".format(roc_path))
        plot_roc(roc_dict, roc_path)
        logging.info("  COMPLETED")
        if args.show:
            plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plots a ROC curve from ApiVectors similarity scores")
    parser.add_argument("scores_folder", help="Directory contianing the JSON files with the scores to be plotted")
    parser.add_argument("-f", "--filter", dest="filter", default="*",
                        help="Wildcard matching patern for the score files")
    parser.add_argument("-s", "--show", dest="show", action="store_true",
                        help="Specify if the final plot must be shown to the user")
    parser.add_argument("-o", "--out_dir", dest="out_dir", default=None,
                        help="Output directory going to contain the plots images")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Show verbose output")
    arguments = parser.parse_args()

    logging.basicConfig(format="%(message)s", level=logging.INFO if arguments.verbose else logging.WARNING)

    if not os.path.isdir(arguments.scores_folder):
        logging.error("Scores folder '{}' does not exist!".format(arguments.scores_folder))
        sys.exit(1)

    if arguments.out_dir is None:
        arguments.out_dir = os.path.join(os.path.dirname(os.path.normpath(arguments.scores_folder)), "plots")
    if not os.path.exists(arguments.out_dir):
        os.makedirs(arguments.out_dir)
    elif not os.path.isdir(arguments.out_dir):
        print("Invalid output dir '{}'".format(arguments.out_dir))
        sys.exit(1)

    main(arguments)
