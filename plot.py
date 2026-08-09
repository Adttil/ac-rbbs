import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


TIME_UNIT_TO_MILLISECONDS = {
    "ns": 1e-6,
    "us": 1e-3,
    "ms": 1.0,
    "s": 1e3,
}
BENCHMARK_NAME = re.compile(
    r"^(experiment[12])/([^/]+)/([^/]+)/attributes:(\d+)/disclosed:(\d+)"
    r"(?:/(?:iterations:\d+|repeats:\d+|process_time|manual_time|real_time|threads:\d+))*$"
)
MARKERS = ("o", "s", "D", "^", "v", "P", "X", "*", "<", ">", "h", "p")
LINESTYLES = ("-", "--", ":", "-.")


def prompt_path(prompt):
    while True:
        try:
            value = input(prompt).strip()
        except EOFError as error:
            raise ValueError("missing path and no interactive input is available") from error

        if value:
            return Path(value).expanduser()

        print("Path cannot be empty.")


def prompt_time_type():
    choices = {
        "1": "real",
        "2": "cpu",
    }
    while True:
        print("Time measurement:")
        print("  1. Real time")
        print("  2. CPU time")
        try:
            choice = input("Select [1/2]: ").strip()
        except EOFError as error:
            raise ValueError(
                "missing time selection and no interactive input is available"
            ) from error

        if choice in choices:
            return choices[choice]
        print("Please enter 1 or 2.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Plot anonymous credential benchmark results."
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="source",
        type=Path,
        help="Google Benchmark JSON file",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="directory in which generated plots are saved",
    )
    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument(
        "--real-time",
        dest="time_type",
        action="store_const",
        const="real",
        help="plot real time",
    )
    time_group.add_argument(
        "--cpu-time",
        dest="time_type",
        action="store_const",
        const="cpu",
        help="plot CPU time",
    )
    arguments = parser.parse_args()

    if arguments.source is None:
        arguments.source = prompt_path("Benchmark JSON source: ")
    if arguments.output is None:
        arguments.output = prompt_path("Plot output directory: ")
    if arguments.time_type is None:
        arguments.time_type = prompt_time_type()

    return arguments


def parse_benchmark_name(name):
    match = BENCHMARK_NAME.fullmatch(name)
    if match is None:
        return None

    experiment, scheme, operation, attributes, disclosed = match.groups()
    return experiment, scheme, operation, int(attributes), int(disclosed)


def load_benchmarks(source, time_type):
    if not source.is_file():
        raise FileNotFoundError(f"benchmark JSON file does not exist: {source}")

    with source.open(encoding="utf-8") as file:
        document = json.load(file)

    if not isinstance(document.get("benchmarks"), list):
        raise ValueError("source is not a Google Benchmark JSON document")

    iterations = defaultdict(list)
    aggregate_means = defaultdict(list)
    for benchmark in document["benchmarks"]:
        name = benchmark.get("run_name", benchmark.get("name", ""))
        key = parse_benchmark_name(name)
        if key is None:
            continue
        if benchmark.get("error_occurred", False):
            raise ValueError(
                f"benchmark failed: {name}: "
                f"{benchmark.get('error_message', 'unknown error')}"
            )

        time_unit = benchmark.get("time_unit")
        if time_unit not in TIME_UNIT_TO_MILLISECONDS:
            raise ValueError(f"unsupported time unit for {name}: {time_unit}")
        time_field = f"{time_type}_time"
        if time_field not in benchmark:
            raise ValueError(f"benchmark has no {time_type} time: {name}")

        time = benchmark[time_field] * TIME_UNIT_TO_MILLISECONDS[time_unit]
        if benchmark.get("run_type", "iteration") == "iteration":
            iterations[key].append(time)
        elif benchmark.get("aggregate_name") == "mean":
            aggregate_means[key].append(time)

    values = {}
    for key in dict.fromkeys((*iterations, *aggregate_means)):
        samples = iterations[key] or aggregate_means[key]
        values[key] = sum(samples) / len(samples)

    if not values:
        raise ValueError("source contains no recognized experiment benchmarks")

    return values


def get_schemes(benchmarks, experiment):
    schemes = list(
        dict.fromkeys(key[1] for key in benchmarks if key[0] == experiment)
    )
    if not schemes:
        raise ValueError(f"source contains no benchmarks for {experiment}")
    return schemes


def get_sample_points(benchmarks, experiment):
    x_index = 3 if experiment == "experiment1" else 4
    points = sorted(
        {
            key[x_index]
            for key in benchmarks
            if key[0] == experiment and key[2] == "pres"
        }
    )
    if not points:
        raise ValueError(f"source contains no presentation benchmarks for {experiment}")
    return points


def get_series(benchmarks, experiment, scheme, operation):
    x_index = 3 if experiment == "experiment1" else 4
    return {
        key[x_index]: value
        for key, value in benchmarks.items()
        if key[0] == experiment and key[1] == scheme and key[2] == operation
    }


def load_series(benchmarks, experiment, scheme, operation, x):
    name = f"{experiment}/{scheme}/{operation}"
    series = get_series(benchmarks, experiment, scheme, operation)
    if not series:
        raise ValueError(f"missing benchmark series: {name}")

    missing = [value for value in x if value not in series]
    extra = [value for value in series if value not in x]
    if missing or extra:
        raise ValueError(
            f"{name} has inconsistent sample points; missing: {missing}, extra: {extra}"
        )
    return np.array([series[value] for value in x])


def has_cache_benchmarks(benchmarks, experiment, scheme):
    has_preprocess = bool(get_series(benchmarks, experiment, scheme, "preprocess"))
    has_pres_with_cache = bool(
        get_series(benchmarks, experiment, scheme, "pres_with_cache")
    )
    if has_preprocess != has_pres_with_cache:
        raise ValueError(
            f"{experiment}/{scheme} must provide both preprocess and "
            "pres_with_cache benchmarks"
        )
    return has_preprocess


def load_experiment(benchmarks, experiment):
    schemes = get_schemes(benchmarks, experiment)
    x = get_sample_points(benchmarks, experiment)
    series = {}

    for scheme in schemes:
        values = {
            "pres": load_series(benchmarks, experiment, scheme, "pres", x),
            "verify": load_series(benchmarks, experiment, scheme, "verify", x),
        }
        if has_cache_benchmarks(benchmarks, experiment, scheme):
            values["preprocess"] = load_series(
                benchmarks, experiment, scheme, "preprocess", x
            )
            values["pres_with_cache"] = load_series(
                benchmarks, experiment, scheme, "pres_with_cache", x
            )
        series[scheme] = values

    return schemes, x, series


def get_colors(count):
    if count <= 10:
        colormap = plt.get_cmap("tab10")
        return [colormap(index) for index in range(count)]
    elif count <= 20:
        colormap = plt.get_cmap("tab20")
        return [colormap(index) for index in range(count)]

    colormap = plt.get_cmap("hsv")
    return [colormap(index / count) for index in range(count)]


def save_plot(output, filename):
    plt.tight_layout()
    plt.savefig(output / filename, dpi=200)
    plt.close()


def plot_lines(output, filename, schemes, colors, x, ys, xlabel):
    plt.figure(figsize=(9, 5.5))

    for index, scheme in enumerate(schemes):
        plt.plot(
            x,
            ys[scheme],
            label=scheme,
            color=colors[index],
            marker=MARKERS[index % len(MARKERS)],
            linestyle=LINESTYLES[(index // len(MARKERS)) % len(LINESTYLES)],
        )

    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.legend(loc="best")
    plt.xlabel(xlabel)
    plt.ylabel("time cost (ms)")
    plt.grid(True, alpha=0.3)
    save_plot(output, filename)


def plot_pres_bars(
    output,
    filename,
    schemes,
    colors,
    x,
    series,
    xlabel,
):
    positions = np.arange(len(x))
    width = 0.8 / len(schemes)

    plt.figure(figsize=(9, 5.5))
    for index, scheme in enumerate(schemes):
        bar_positions = positions + (index - (len(schemes) - 1) / 2) * width
        values = series[scheme]
        if "preprocess" in values:
            online = values["pres_with_cache"]
            plt.bar(
                bar_positions,
                online,
                width,
                label=f"{scheme} Online",
                color=colors[index],
                edgecolor="black",
                linewidth=0.5,
            )
            plt.bar(
                bar_positions,
                values["preprocess"],
                width,
                bottom=online,
                label=f"{scheme} Preprocess",
                color=colors[index],
                edgecolor="black",
                linewidth=0.5,
                hatch="//",
                alpha=0.55,
            )
        else:
            plt.bar(
                bar_positions,
                values["pres"],
                width,
                label=scheme,
                color=colors[index],
                edgecolor="black",
                linewidth=0.5,
            )

    plt.xticks(positions, x)
    plt.xlim(left=-0.5, right=len(x) - 0.5)
    plt.ylim(bottom=0)
    plt.legend(loc="best")
    plt.xlabel(xlabel)
    plt.ylabel("time cost (ms)")
    plt.grid(True, axis="y", alpha=0.3)
    save_plot(output, filename)


def plot_experiment(benchmarks, output, experiment):
    schemes, x, series = load_experiment(benchmarks, experiment)
    colors = get_colors(len(schemes))
    xlabel = (
        "total attributes count"
        if experiment == "experiment1"
        else "disclosed attributes count"
    )

    plot_lines(
        output,
        f"{experiment}_verify.png",
        schemes,
        colors,
        x,
        {scheme: series[scheme]["verify"] for scheme in schemes},
        xlabel,
    )
    plot_pres_bars(
        output,
        f"{experiment}_pres.png",
        schemes,
        colors,
        x,
        series,
        xlabel,
    )

    cache_hit = {}
    for scheme in schemes:
        values = series[scheme]
        if "preprocess" in values:
            cache_hit[scheme] = (
                0.5 * values["preprocess"] + values["pres_with_cache"]
            )
        else:
            cache_hit[scheme] = values["pres"]

    plot_lines(
        output,
        f"{experiment}_pres_50_percent_cache_hit.png",
        schemes,
        colors,
        x,
        cache_hit,
        xlabel,
    )


def main():
    arguments = parse_arguments()
    source = arguments.source.expanduser().resolve()
    output = arguments.output.expanduser().resolve()
    if output.exists() and not output.is_dir():
        raise NotADirectoryError(f"plot output path is not a directory: {output}")

    benchmarks = load_benchmarks(source, arguments.time_type)
    output.mkdir(parents=True, exist_ok=True)
    plot_experiment(benchmarks, output, "experiment1")
    plot_experiment(benchmarks, output, "experiment2")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: {error}") from error
