#!/usr/bin/python3
import argparse
import itertools
import json
import math
import os
import sys
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict, Counter
from sklearn.metrics import multilabel_confusion_matrix, confusion_matrix, classification_report
from mpl_toolkits.axes_grid1 import make_axes_locatable
from matplotlib.ticker import AutoMinorLocator


def restricted_float(x):
    try:
        x = float(x)
    except ValueError:
        raise argparse.ArgumentTypeError("{} not a floating-point literal".format(x))

    if x < 0.0 or x > 1.0:
        raise argparse.ArgumentTypeError("{} not in range [0.0, 1.0]".format(x))
    return x


def classify_dataset(rule, threshold, samples_dict, scores_dict):
    y_true = []
    y_pred = []
    matched_samples = defaultdict(set)
    for sample, data in scores_dict.items():
        true_class = samples_dict["classification"][sample]

        class_frequency = Counter()
        class_frequency_per_score = defaultdict(Counter)
        for other_sample, score in data.items():
            other_class = samples_dict["classification"][other_sample]
            if score > threshold:
                class_frequency[other_class] += 1
                class_frequency_per_score[score][other_class] += 1

        pred_class = "Unknown"
        if rule == "max" and len(class_frequency_per_score) > 0:
            # Max similarity score among the other samples
            max_score = sorted(class_frequency_per_score, reverse=True)[0]
            # APT classes in which at least a sample obtained the max similarity score
            max_score_classes = class_frequency_per_score[max_score]
            if len(max_score_classes) == 1:
                # Only one APT class has a sample with the maximum similarity score
                pred_class = list(max_score_classes)[0]
            else:
                # More than one APT class has a sample having the maximum similarity score, hence we have to look also
                # at the most frequent class among the one with maximum scores (i.e., the class with the maximum number
                # of samples whose similarity score is above the threshold and has the maximum score, normalized
                # by the total number of samples in the dataset that belong to that class).
                for max_score_class in max_score_classes:  # normalization
                    max_score_classes[max_score_class] /= samples_dict["per_apt"][max_score_class]["total"]

                most_frequent_max_classes = max_score_classes.most_common(2)
                if most_frequent_max_classes[0][1] != most_frequent_max_classes[1][1]:
                    # the most frequent classes have different frequency, so we can choose the most frequent one
                    pred_class = most_frequent_max_classes[0][0]
                else:
                    # the most frequent classes have the same frequency, we will look at the class with most frequent
                    # samples above the threshold (not necessarily having the maximum score)
                    class_frequency = Counter({k: class_frequency[k] for k in max_score_classes})

        if (rule == "knn" or pred_class == "Unknown") and len(class_frequency) > 0:
            for frequent_class in class_frequency:
                class_frequency[frequent_class] /= samples_dict["per_apt"][frequent_class]["total"]
            frequent_classes = class_frequency.most_common()
            most_frequent_classes = set()
            for frequent_class, frequency in frequent_classes:
                if frequency < frequent_classes[0][1]:
                    break
                most_frequent_classes.add(frequent_class)
            if len(most_frequent_classes) == 1:
                pred_class = most_frequent_classes.pop()

        y_true.append(true_class)
        y_pred.append(pred_class)
    return y_true, y_pred


def plot_confusion_matrix(cm, classes, out_file, params=None, apt=None, normalize=True, cmap=None):
    if normalize:
        # cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        a = cm.astype("float")
        b = cm.sum(axis=1)[:, np.newaxis]
        # ignoring when b == 0 to avoid NaN when computing a / b
        cm = np.divide(a, b, out=np.zeros_like(a), where=b != 0)
        title = "Confusion matrix, normalized"
    else:
        title = "Confusion matrix, non normalized"

    if apt is not None:
        title += " ({})".format(apt)

    if cmap is None:
        cmap = plt.get_cmap('Blues')

    fig, ax = plt.subplots()
    dpi = fig.get_dpi()
    fig.set_size_inches(900.0 / float(dpi), 770.0 / float(dpi))
    im = ax.imshow(cm, interpolation='nearest', cmap=cmap)

    ax.set(xticks=np.arange(cm.shape[1]), yticks=np.arange(cm.shape[0]),
           xticklabels=classes, yticklabels=classes,
           xlabel='Predicted label', ylabel='True label',
           title=title)

    if normalize:
        im.set_clim(0, 1.0)
    ax.figure.colorbar(im, fraction=0.046, pad=0.04)

    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    fmt = '{0:.2f}' if normalize else '{}'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, fmt.format(round(cm[i, j], 2) if normalize else cm[i, j]),
                 ha="center", va="center",
                 fontsize=8 if apt is None else 10,
                 color="white" if cm[i, j] > thresh else "black")

    if params is not None:
        params_text = "\n".join([
            "alg. = {}".format(params["rule"]),
            "threshold = {}".format(params["threshold"]),
            "imports = {}".format(params["imports_type"]),
            "weights = {}".format(params["weights"]),
            "size = {}".format(params["size"])
        ])
        props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
        fig.text(0.9825, 0.025, params_text, fontsize=8, va="bottom", ha='right', bbox=props)

    plt.tight_layout()
    fig.savefig(out_file)


def plot_classification(confusion_path, y_true, y_pred, params):
    np.set_printoptions(precision=2)

    stats = classification_report(y_true, y_pred, output_dict=True)
    stats["per_apt"] = {}
    apt_classes = sorted(set(y_true))
    mcnf_matrix = multilabel_confusion_matrix(y_true, y_pred, labels=apt_classes)
    for index, apt_cnf_matrix in enumerate(mcnf_matrix):
        apt = apt_classes[index]
        classes = ["Non " + apt, apt]
        apt_cnf_file = os.path.join(confusion_path, "confusion_{}.svgz".format(apt.replace(" ", "_")))
        plot_confusion_matrix(apt_cnf_matrix, classes, apt_cnf_file, params, apt)
        plt.close()

        tn, fp, fn, tp = [x.item() for x in apt_cnf_matrix.ravel()]
        stats[apt].update({
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "accuracy": (tp + tn) / (tp + tn + fp + fn)
        })
        stats["per_apt"][apt] = stats.pop(apt)
    if "Unknown" in stats:
        del stats["Unknown"]

    apt_classes.append("Unknown")
    cnf_matrix = confusion_matrix(y_true, y_pred, labels=apt_classes)
    cnf_matrix = cnf_matrix[:-1, :]  # remove unnecessary Unknown row
    cnf_file = os.path.join(confusion_path, "confusion.svgz")
    plot_confusion_matrix(cnf_matrix, apt_classes, cnf_file, params)
    return stats


def main(scores_file, rule, threshold, out_dir, show, params_box):
    with open(scores_file, mode="r") as fp:
        scores_dict = json.load(fp)

        dataset_path = os.path.normpath(os.path.join(os.path.dirname(scores_file), scores_dict["dataset"]))
        if not os.path.isfile(dataset_path):
            print("Dataset file '{}' does not exist".format(dataset_path))
            sys.exit(1)

        with open(dataset_path, mode="r") as dfp:
            dataset_dict = json.load(dfp)

            y_true, y_pred = classify_dataset(rule, threshold, dataset_dict["samples"], scores_dict["scores"])

            base = scores_dict["base"]
            confusion_path = os.path.join(out_dir,
                                          "cnf_{}_{}_{}".format(base["imports_type"], base["weights"], base["size"]),
                                          "{}_{:04.2f}".format(rule, threshold))
            if not os.path.exists(confusion_path):
                os.makedirs(confusion_path)

            params = dict({"rule": rule, "threshold": threshold}, **base) if params_box else None
            stats = plot_classification(confusion_path, y_true, y_pred, params)

            stats_file = os.path.join(confusion_path, "classification_stats.json")
            with open(stats_file, mode="w") as stats_fp:
                json.dump(stats, stats_fp, indent=4)

            if show:
                plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Matches ApiVectors against each other and calculates matching stats")
    parser.add_argument("scores_file",
                        help="JSON file containing all the matching scores to plot")
    parser.add_argument("-r", "--rule", choices=["max", "knn"], default="max",
                        help="Rule for choosing the label of a sample: max score or most frequent neighbor label")
    parser.add_argument("-t", "--threshold", type=restricted_float, default=0.5,
                        help="Threshold value after which two samples are considered of the same APT group")
    parser.add_argument("-p", "--params_box", action="store_true",
                        help="Show a box with the parameters used to generate the confusion matrix plot")
    parser.add_argument("-s", "--show", action="store_true",
                        help="Specify if the final plot must be shown to the user")
    parser.add_argument("-o", "--out_dir", default=None,
                        help="Output directory going to contain the plots images")
    args = parser.parse_args()

    if not os.path.isfile(args.scores_file):
        print("Scores file '{}' does not exist".format(args.scores_file))
        sys.exit(1)

    if args.out_dir is None:
        args.out_dir = os.path.join(os.path.dirname(os.path.dirname(args.scores_file)), "plots")
    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)
    elif not os.path.isdir(args.out_dir):
        print("Invalid output dir '{}'".format(args.out_dir))
        sys.exit(1)

    main(**vars(args))
