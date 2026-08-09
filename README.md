# Benchmarks of Anonymous Credential Schemes
[![license](https://img.shields.io/github/license/Adttil/ac-rbbs.svg)](https://github.com/Adttil/ac-rbbs/blob/master/LICENSE.txt)

This repository provides the reference implementation and performance evaluation of our redactable BBS anonymous credential scheme. For comparative evaluation, it also includes implementations of three existing anonymous credential schemes—RPS, BBS, and MoniPoly—as baselines.

The benchmark evaluates presentation and verification costs, and the resulting JSON data can be visualized with the included plotting script.

## Requirements

### Benchmarks

- CMake 3.28 or later
- A compiler and standard library with C++23 support

### Plotting

- Python 3
- Matplotlib and NumPy (see [Dependencies](#dependencies) for details)

## Installation

This describes the installation process using cmake. As pre-requisites, you'll need git and cmake installed.

```console
# Check out the repository.
$ git clone https://github.com/Adttil/ac-rbbs.git

# Go to the repository root directory.
$ cd ac-rbbs

# Make a build directory to place the build output.
$ cmake -E make_directory "build"

# Generate build system files and download the C++ dependencies.
$ cmake -DCMAKE_BUILD_TYPE=Release -S . -B "build"

# Build the benchmark executable.
$ cmake --build "build" --config Release
```

This builds the `benchmark` executable.

## Running Benchmarks

Run the benchmarks with the default experiment configuration and write the results to a JSON file as follows:

```console
$ cmake -E make_directory "out"
$ ./build/benchmark --benchmark_out=out/results.json
```

The benchmark comprises two experiments. Experiment 1 varies the total number of attributes while fixing the number of disclosed attributes. Experiment 2 varies the number of disclosed attributes while fixing the total number of attributes. The experiment parameters can be configured using the following command-line options:

| Option | Description | Default |
| --- | --- | ---: |
| `--exp1-disclosed` | Fixed disclosed attribute count | 3 |
| `--exp1-start` | First total attribute count | 10 |
| `--exp1-step` | Total attribute sampling interval | 10 |
| `--exp1-samples` | Number of samples | 10 |
| `--exp2-total` | Fixed total attribute count | 64 |
| `--exp2-start` | First disclosed attribute count | 3 |
| `--exp2-step` | Disclosed attribute sampling interval | 3 |
| `--exp2-samples` | Number of samples | 10 |

The executable also accepts Google Benchmark options. The most relevant ones for these experiments are:

| Option | Description |
| --- | --- |
| `--benchmark_min_time=<time>` | Set the minimum time or explicit iteration count |
| `--benchmark_min_warmup_time=<time>` | Set the minimum warm-up time |
| `--benchmark_repetitions=<count>` | Repeat each benchmark the given number of times |
| `--benchmark_out=<file>` | Write benchmark results to a file |

Use `--help` to display all project-specific and Google Benchmark options.

## Plotting

Generate plots from a Google Benchmark JSON file using either real time or CPU time:

```console
python plot.py -i out/results.json -o out/plots --real-time
python plot.py --input out/results.json -o out/plots --cpu-time
```

`--real-time` and `--cpu-time` are mutually exclusive. If the input path, output path, or time selection is omitted, the script interactively prompts for the missing value.

The script generates six images:

### `experiment1_verify.png`/`experiment2_verify.png`

Line charts of the verification cost.

### `experiment1_pres.png`/`experiment2_pres.png`

Bar charts of the presentation cost under the corresponding experiment settings. For schemes with presentation caching, each bar is divided into `Preprocess` and `Online` stages.

### `experiment1_pres_50_percent_cache_hit.png`/`experiment2_pres_50_percent_cache_hit.png`

Line charts of the expected presentation cost at a 50% cache hit rate. For schemes with presentation caching, the expected cost is calculated as `pres_with_cache + 0.5 * preprocess`; for other schemes, the complete `pres` cost is used.

## Dependencies

### Benchmarks

| Component | Version | Source |
| --- | --- | --- |
| crypto12381 | 0.2.0 | [github.com/Adttil/crypto12381](https://github.com/Adttil/crypto12381) |
| cxxopts | 3.3.1 | [github.com/jarro2783/cxxopts](https://github.com/jarro2783/cxxopts) |
| Google Benchmark | 1.9.5 | [github.com/google/benchmark](https://github.com/google/benchmark) |

The benchmark dependencies are downloaded and built automatically by CMake.

### Plotting

| Component | Version | Source |
| --- | --- | --- |
| Matplotlib | `>=3.4.2` | [github.com/matplotlib/matplotlib](https://github.com/matplotlib/matplotlib) |
| NumPy | `>=1.25.0` | [github.com/numpy/numpy](https://github.com/numpy/numpy) |

They can be installed with:

```console
$ python -m pip install matplotlib numpy
```
