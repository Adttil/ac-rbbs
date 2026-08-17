import argparse
import inspect
import json
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from matplotlib.transforms import Bbox


plt.rcParams["pdf.fonttype"] = 42

TIME_UNIT_TO_MILLISECONDS = {
    "ns": 1e-6,
    "us": 1e-3,
    "ms": 1.0,
    "s": 1e3,
}
BENCHMARK_NAME = re.compile(
    r"^([^/]+)/([^/]+)/attributes:(\d+)/disclosed:(\d+)"
    r"(?:/(?:iterations:\d+|repeats:\d+|process_time|manual_time|real_time|threads:\d+))*$"
)


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

    scheme, operation, attributes, disclosed = match.groups()
    return scheme, operation, int(attributes), int(disclosed)


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
        raise ValueError("source contains no recognized benchmarks")

    return values


def get_schemes(benchmarks, operation):
    return list(
        dict.fromkeys(
            key[0]
            for key in benchmarks
            if key[1] == operation
        )
    )


def load_surfaces(benchmarks, operation):
    schemes = get_schemes(benchmarks, operation)
    if not schemes:
        return None

    attributes = sorted(
        {
            key[2]
            for key in benchmarks
            if key[1] == operation
        }
    )
    disclosed = sorted(
        {
            key[3]
            for key in benchmarks
            if key[1] == operation
        }
    )
    surfaces = {}
    for scheme in schemes:
        name = f"{scheme}/{operation}"
        values = {
            (key[2], key[3]): value
            for key, value in benchmarks.items()
            if key[0] == scheme and key[1] == operation
        }
        missing = [
            (attribute_count, disclosed_count)
            for disclosed_count in disclosed
            for attribute_count in attributes
            if (attribute_count, disclosed_count) not in values
        ]
        if missing:
            raise ValueError(f"{name} has incomplete sampling grid; missing: {missing}")
        surfaces[scheme] = np.array(
            [
                [values[attribute_count, disclosed_count] for attribute_count in attributes]
                for disclosed_count in disclosed
            ]
        )

    return schemes, attributes, disclosed, surfaces


def get_colors(count):
    if count <= 10:
        colormap = plt.get_cmap("tab10")
        return [colormap(index) for index in range(count)]
    elif count <= 20:
        colormap = plt.get_cmap("tab20")
        return [colormap(index) for index in range(count)]

    colormap = plt.get_cmap("hsv")
    return [colormap(index / count) for index in range(count)]


def save_plot(figure, output, filename):
    figure.tight_layout()
    figure.canvas.draw()
    tight_bbox = figure.get_tightbbox(figure.canvas.get_renderer())
    bbox = Bbox.from_extents(
        tight_bbox.x0 - 0.05,
        tight_bbox.y0 + 0.45,
        tight_bbox.x1,
        tight_bbox.y1,
    )
    figure.savefig(
        output / filename,
        dpi=200,
        bbox_inches=bbox,
        pad_inches=0.05,
    )
    plt.close(figure)


def remove_legacy_3d_axis_padding(axes):
    if not inspect.signature(axes.zaxis._get_coord_info).parameters:
        return

    for axis in (axes.xaxis, axes.yaxis, axes.zaxis):
        original_get_coord_info = axis._get_coord_info

        def get_coord_info(renderer, original=original_get_coord_info, axis=axis):
            mins, maxs, centers, deltas, _, _ = original(renderer)
            mins += deltas / 4
            maxs -= deltas / 4
            bounds = (
                mins[0],
                maxs[0],
                mins[1],
                maxs[1],
                mins[2],
                maxs[2],
            )
            coordinates = axes.tunit_cube(bounds, axes.M)
            average_z = [
                sum(coordinates[index][2] for index in plane)
                for plane in axis._PLANES
            ]
            highs = np.array(
                [average_z[2 * index] < average_z[2 * index + 1] for index in range(3)]
            )
            return mins, maxs, centers, deltas, coordinates, highs

        axis._get_coord_info = get_coord_info


def plot_surfaces(output, filename, attributes, disclosed, series):
    attribute_grid, disclosed_grid = np.meshgrid(attributes, disclosed)

    figure = plt.figure(figsize=(9, 6.5))
    axes = figure.add_subplot(projection="3d")
    handles = []
    online_handles = []
    for label, values, color, online in series:
        alpha = 0.4 if online else 0.65
        hatch = "//" if online else None
        axes.plot_surface(
            attribute_grid,
            disclosed_grid,
            values,
            color=color,
            alpha=alpha,
            linewidth=0.4,
            edgecolor=color,
            hatch=hatch,
        )
        (online_handles if online else handles).append(
            Patch(
                facecolor=color,
                edgecolor=color,
                alpha=alpha,
                hatch=hatch,
                label=label,
            )
        )

    axes.set_xticks(attributes)
    axes.set_yticks(disclosed)
    axes.set_zlim(bottom=0)
    remove_legacy_3d_axis_padding(axes)
    axes.set_xlabel("total attributes count")
    axes.set_ylabel("disclosed attributes count")
    axes.set_zlabel("time cost (ms)")
    axes.set_proj_type("ortho")
    axes.view_init(elev=20, azim=-127.5)
    axes.legend(handles=handles + online_handles, loc="best")
    save_plot(figure, output, filename)


def plot_benchmarks(benchmarks, output):
    verify = load_surfaces(benchmarks, "verify")
    if verify is not None:
        schemes, attributes, disclosed, surfaces = verify
        colors = get_colors(len(schemes))
        plot_surfaces(
            output,
            "verify.pdf",
            attributes,
            disclosed,
            [
                (scheme, surfaces[scheme], colors[index], False)
                for index, scheme in enumerate(schemes)
            ],
        )

    presentations = load_surfaces(benchmarks, "pres")
    if presentations is None:
        return

    schemes, attributes, disclosed, surfaces = presentations
    colors = get_colors(len(schemes))
    online = load_surfaces(benchmarks, "pres_with_cache")
    online_surfaces = {}
    if online is not None:
        online_schemes, online_attributes, online_disclosed, online_surfaces = online
        if online_attributes != attributes or online_disclosed != disclosed:
            raise ValueError(
                "pres_with_cache has sample points inconsistent with pres"
            )
        extra_schemes = [scheme for scheme in online_schemes if scheme not in schemes]
        if extra_schemes:
            raise ValueError(
                f"pres_with_cache has schemes missing from pres: {extra_schemes}"
            )

    series = []
    for index, scheme in enumerate(schemes):
        series.append((scheme, surfaces[scheme], colors[index], False))
        if scheme in online_surfaces:
            series.append(
                (
                    f"{scheme} Online",
                    online_surfaces[scheme],
                    colors[index],
                    True,
                )
            )

    plot_surfaces(
        output,
        "pres.pdf",
        attributes,
        disclosed,
        series,
    )


def main():
    arguments = parse_arguments()
    source = arguments.source.expanduser().resolve()
    output = arguments.output.expanduser().resolve()
    if output.exists() and not output.is_dir():
        raise NotADirectoryError(f"plot output path is not a directory: {output}")

    benchmarks = load_benchmarks(source, arguments.time_type)
    output.mkdir(parents=True, exist_ok=True)
    plot_benchmarks(benchmarks, output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: {error}") from error
