#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <cxxopts.hpp>
#include <crypto12381/crypto12381.hpp>

#include <schemes.hpp>

namespace ac = anonymous_credentials;

template<typename AC>
concept anonymous_credential = requires(
    const AC& ac,
    size_t n,
    crypto12381::RandomEngine& random,
    const typename AC::Keys& keys,
    const typename AC::PublicKey& pk,
    const typename AC::UserPublicKey& upk,
    const typename AC::UserSecretKey& usk,
    std::span<const crypto12381::serialized_field<crypto12381::Zp>> attr,
    std::span<const size_t> I,
    std::string_view m,
    const typename AC::Signature& sig,
    const typename AC::RedactCache& redact_cache,
    const typename AC::PresInfo& pres_info
)
{
    { ac.name() } -> std::same_as<std::string_view>;
    { ac.keygen(n, random) } -> std::same_as<typename AC::Keys>;
    { ac.user_keygen(pk, random) } -> std::same_as<typename AC::UserKeys>;
    { ac.generate_attributes(pk, n, random) } -> std::same_as<std::vector<crypto12381::serialized_field<crypto12381::Zp>>>;
    { ac.issue(keys, upk, attr, random) } -> std::same_as<typename AC::Signature>;
    { ac.redact(attr, sig, usk, I, pk) } -> std::same_as<typename AC::RedactCache>;
    { ac.pres(m, attr, sig, I, redact_cache, usk, pk, random) } -> std::same_as<typename AC::PresInfo>;
    { ac.verify(m, attr, I, pres_info, pk) } -> std::same_as<bool>;
};

struct BenchmarkResult
{
    std::chrono::microseconds redact_time;
    std::chrono::microseconds pres_time;
    std::chrono::microseconds verification_time;
};

struct Experiment1Config
{
    size_t n_disclosed = 3uz;
    size_t first = 10uz;
    size_t interval = 10uz;
    size_t samples = 10uz;
};

struct Experiment2Config
{
    size_t n_attributes = 64uz;
    size_t first = 3uz;
    size_t interval = 3uz;
    size_t samples = 10uz;
};

struct BenchmarkConfig
{
    size_t repetitions = 100uz;
    Experiment1Config experiment1;
    Experiment2Config experiment2;
};

template<typename Operation>
decltype(auto) benchmark(size_t repetitions, std::chrono::microseconds& total_time, Operation&& operation)
{
    const auto start = std::chrono::steady_clock::now();
    for(size_t i = 0uz; i < repetitions; ++i)
    {
        operation();
    }
    total_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
    return operation();
}

template<anonymous_credential AC>
BenchmarkResult benchmark_scheme(const AC& ac, size_t n, std::span<const size_t> I, size_t repetitions)
{
    BenchmarkResult result;
    auto random = crypto12381::create_random_engine("seed");
    const auto keys = ac.keygen(n, random);
    const auto& [sk, pk] = keys;
    const auto attr = ac.generate_attributes(pk, n, random);
    const auto [usk, upk] = ac.user_keygen(pk, random);
    const auto sig = ac.issue(keys, upk, attr, random);

    const auto redact_cache = benchmark(repetitions, result.redact_time, [&]
    {
        return ac.redact(attr, sig, usk, I, pk);
    });

    constexpr std::string_view m = "anonymous credential benchmark";
    const auto pres_info = benchmark(repetitions, result.pres_time, [&]
    {
        return ac.pres(m, attr, sig, I, redact_cache, usk, pk, random);
    });

    const bool valid = benchmark(repetitions, result.verification_time, [&]
    {
        return ac.verify(m, attr, I, pres_info, pk);
    });
    if(not valid)
    {
        throw std::runtime_error{ std::string{ ac.name() } + " verification failed" };
    }

    std::cout << "  " << ac.name()
        << ": redact=" << result.redact_time.count()
        << " us, pres=" << result.pres_time.count()
        << " us, verify=" << result.verification_time.count() << " us\n";

    return result;
}

void validate(const BenchmarkConfig& config)
{
    const auto& experiment_1 = config.experiment1;
    const auto& experiment_2 = config.experiment2;
    if(config.repetitions == 0uz || experiment_1.samples == 0uz || experiment_2.samples == 0uz)
    {
        throw std::invalid_argument{ "repetitions and sample counts must be positive" };
    }
    if(experiment_1.first == 0uz || experiment_2.n_attributes == 0uz)
    {
        throw std::invalid_argument{ "total attribute counts must be positive" };
    }
    if(experiment_1.n_disclosed > experiment_1.first)
    {
        throw std::invalid_argument{ "experiment 1 disclosed attribute count exceeds its first total attribute count" };
    }

    const auto experiment_2_last = experiment_2.first + experiment_2.interval * (experiment_2.samples - 1uz);
    if(experiment_2_last > experiment_2.n_attributes)
    {
        throw std::invalid_argument{ "experiment 2 disclosed attribute count exceeds its total attribute count" };
    }
}

template<anonymous_credential...AC>
void run_experiment_1(const BenchmarkConfig& config, std::span<const size_t> indexes, const AC&...ac)
{
    std::ofstream output{ "bench_result.csv" };
    if(not output)
    {
        throw std::runtime_error{ "failed to open output file: bench_result.csv" };
    }

    const auto& experiment = config.experiment1;
    output << "total_attributes";
    ((output << ',' << ac.name() << "_redact"
        << ',' << ac.name() << "_pres"
        << ',' << ac.name() << "_verify"), ...);
    output << '\n';
    const auto disclosed_indexes = indexes.first(experiment.n_disclosed);

    for(size_t sample = 0uz; sample < experiment.samples; ++sample)
    {
        const auto attribute_count = experiment.first + experiment.interval * sample;
        std::cout << "experiment 1: total attributes=" << attribute_count
            << ", disclosed attributes=" << disclosed_indexes.size() << '\n';
        const std::array bench_results{
            benchmark_scheme(ac, attribute_count, disclosed_indexes, config.repetitions)... 
        };
        output << attribute_count;
        for(const auto& result : bench_results)
        {
            output << ',' << result.redact_time.count()
                << ',' << result.pres_time.count()
                << ',' << result.verification_time.count();
        }
        output << '\n';
    }
}

template<anonymous_credential...AC>
void run_experiment_2(const BenchmarkConfig& config, std::span<const size_t> indexes, const AC&...ac)
{
    std::ofstream output{ "bench_disclosed_result.csv" };
    if(not output)
    {
        throw std::runtime_error{ "failed to open output file: bench_disclosed_result.csv" };
    }

    const auto& experiment = config.experiment2;
    output << "disclosed_attributes";
    ((output << ',' << ac.name() << "_redact"
        << ',' << ac.name() << "_pres"
        << ',' << ac.name() << "_verify"), ...);
    output << '\n';

    for(size_t sample = 0uz; sample < experiment.samples; ++sample)
    {
        const auto disclosed_count = experiment.first + experiment.interval * sample;
        const auto disclosed_indexes = indexes.first(disclosed_count);
        std::cout << "experiment 2: total attributes=" << experiment.n_attributes
            << ", disclosed attributes=" << disclosed_count << '\n';
        const std::array bench_results{ 
            benchmark_scheme(ac, experiment.n_attributes, disclosed_indexes, config.repetitions)... 
        };
        output << disclosed_count;
        for(const auto& result : bench_results)
        {
            output << ',' << result.redact_time.count()
                << ',' << result.pres_time.count()
                << ',' << result.verification_time.count();
        }
        output << '\n';
    }
}

template<anonymous_credential...AC>
void run_benchmarks(const BenchmarkConfig& config, const AC&...ac)
{
    const auto& [_, config1, config2] = config;
    const auto n_attributes_max = std::max(
        config1.first + config1.interval * (config1.samples - 1uz), 
        config2.n_attributes
    );
    std::vector<size_t> indexes(n_attributes_max);
    std::iota(indexes.begin(), indexes.end(), 0uz);

    run_experiment_1(config, indexes, ac...);
    run_experiment_2(config, indexes, ac...);
}

int main(int argc, char* argv[])
{
    BenchmarkConfig config;
    cxxopts::Options options{ "benchmark", "Anonymous credential benchmarks" };
    const auto with_default = [](auto& value)
    {
        return cxxopts::value(value)->default_value(std::to_string(value));
    };

    options.add_options("General")
        ("r,repeat", "Repetitions per benchmark", with_default(config.repetitions))
        ("h,help", "Print help");

    options.add_options("Experiment 1")
        ("exp1-disclosed", "Number of disclosed attributes", with_default(config.experiment1.n_disclosed))
        ("exp1-start", "First total attribute count", with_default(config.experiment1.first))
        ("exp1-step", "Sampling interval", with_default(config.experiment1.interval))
        ("exp1-samples", "Number of samples", with_default(config.experiment1.samples));

    options.add_options("Experiment 2")
        ("exp2-total", "Fixed total attribute count", with_default(config.experiment2.n_attributes))
        ("exp2-start", "First disclosed attribute count", with_default(config.experiment2.first))
        ("exp2-step", "Sampling interval", with_default(config.experiment2.interval))
        ("exp2-samples", "Number of samples", with_default(config.experiment2.samples));

    try
    {
        const auto arguments = options.parse(argc, argv);
        if(arguments.count("help") != 0uz)
        {
            std::cout << options.help();
            return 0;
        }

        validate(config);

        run_benchmarks(config, ac::rps, ac::bbs, ac::monipoly, ac::our_scheme);
        return 0;
    }
    catch(const std::exception& error)
    {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
