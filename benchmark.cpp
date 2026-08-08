#include <algorithm>
#include <concepts>
#include <cstddef>
#include <iostream>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <benchmark/benchmark.h>
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
    const typename AC::PresInfo& pres_info
)
{
    { ac.name() } -> std::same_as<std::string_view>;
    { ac.keygen(n, random) } -> std::same_as<typename AC::Keys>;
    { ac.user_keygen(pk, random) } -> std::same_as<typename AC::UserKeys>;
    { ac.generate_attributes(pk, n, random) } -> std::same_as<std::vector<crypto12381::serialized_field<crypto12381::Zp>>>;
    { ac.issue(keys, upk, attr, random) } -> std::same_as<typename AC::Signature>;
    { ac.pres(m, attr, sig, I, usk, pk, random) } -> std::same_as<typename AC::PresInfo>;
    { ac.verify(m, attr, I, pres_info, pk) } -> std::same_as<bool>;
};

template<typename AC>
concept redactable_anonymous_credential = anonymous_credential<AC> && requires(
    const AC& ac,
    crypto12381::RandomEngine& random,
    const typename AC::PublicKey& pk,
    const typename AC::UserSecretKey& usk,
    std::span<const crypto12381::serialized_field<crypto12381::Zp>> attr,
    std::span<const size_t> I,
    std::string_view m,
    const typename AC::Signature& sig,
    const typename AC::RedactCache& redact_cache
)
{
    { ac.redact(attr, sig, usk, I, pk) } -> std::same_as<typename AC::RedactCache>;
    { ac.pres(m, attr, sig, I, redact_cache, usk, pk, random) } -> std::same_as<typename AC::PresInfo>;
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
    Experiment1Config experiment1;
    Experiment2Config experiment2;
};

void validate(const BenchmarkConfig& config)
{
    const auto& [experiment1, experiment2] = config;
    if(experiment1.samples == 0uz || experiment2.samples == 0uz)
    {
        throw std::invalid_argument{ "sample counts must be positive" };
    }
    if(experiment1.first == 0uz || experiment2.n_attributes == 0uz)
    {
        throw std::invalid_argument{ "total attribute counts must be positive" };
    }
    if(experiment1.n_disclosed > experiment1.first)
    {
        throw std::invalid_argument{ "experiment1 disclosed attribute count exceeds its first total attribute count" };
    }

    const auto experiment2_last = experiment2.first + experiment2.interval * (experiment2.samples - 1uz);
    if(experiment2_last > experiment2.n_attributes)
    {
        throw std::invalid_argument{ "experiment2 disclosed attribute count exceeds its total attribute count" };
    }
}

template<anonymous_credential AC>
void register_scheme_benchmarks(
    std::string_view experiment,
    const AC& ac,
    size_t n,
    std::span<const size_t> I
)
{
    const auto prefix = std::string{ experiment } + '/' + std::string{ ac.name() };
    const auto parameters = "/attributes:" + std::to_string(n) + "/disclosed:" + std::to_string(I.size());

    const auto pres_name = prefix + "/pres" + parameters;
    benchmark::RegisterBenchmark(pres_name.c_str(), [&ac, n, I](benchmark::State& state)
    {
        auto random = crypto12381::create_random_engine("seed");
        const auto keys = ac.keygen(n, random);
        const auto& [sk, pk] = keys;
        const auto attr = ac.generate_attributes(pk, n, random);
        const auto [usk, upk] = ac.user_keygen(pk, random);
        const auto sig = ac.issue(keys, upk, attr, random);

        constexpr std::string_view m = "anonymous credential benchmark";
        for(auto _ : state)
        {
            auto pres_info = ac.pres(m, attr, sig, I, usk, pk, random);
            benchmark::DoNotOptimize(pres_info);
        }
    })->Unit(benchmark::kMicrosecond);

    if constexpr(redactable_anonymous_credential<AC>)
    {
        const auto redact_name = prefix + "/redact" + parameters;
        benchmark::RegisterBenchmark(redact_name.c_str(), [&ac, n, I](benchmark::State& state)
        {
            auto random = crypto12381::create_random_engine("seed");
            const auto keys = ac.keygen(n, random);
            const auto& [sk, pk] = keys;
            const auto attr = ac.generate_attributes(pk, n, random);
            const auto [usk, upk] = ac.user_keygen(pk, random);
            const auto sig = ac.issue(keys, upk, attr, random);

            for(auto _ : state)
            {
                auto redact_cache = ac.redact(attr, sig, usk, I, pk);
                benchmark::DoNotOptimize(redact_cache);
            }
        })->Unit(benchmark::kMicrosecond);

        const auto pres_with_cache_name = prefix + "/pres_with_cache" + parameters;
        benchmark::RegisterBenchmark(pres_with_cache_name.c_str(), [&ac, n, I](benchmark::State& state)
        {
            auto random = crypto12381::create_random_engine("seed");
            const auto keys = ac.keygen(n, random);
            const auto& [sk, pk] = keys;
            const auto attr = ac.generate_attributes(pk, n, random);
            const auto [usk, upk] = ac.user_keygen(pk, random);
            const auto sig = ac.issue(keys, upk, attr, random);
            const auto redact_cache = ac.redact(attr, sig, usk, I, pk);

            constexpr std::string_view m = "anonymous credential benchmark";
            const auto pres_info = ac.pres(m, attr, sig, I, redact_cache, usk, pk, random);
            if(not ac.verify(m, attr, I, pres_info, pk))
            {
                state.SkipWithError("verification failed");
                return;
            }

            for(auto _ : state)
            {
                auto result = ac.pres(m, attr, sig, I, redact_cache, usk, pk, random);
                benchmark::DoNotOptimize(result);
            }
        })->Unit(benchmark::kMicrosecond);
    }

    const auto verify_name = prefix + "/verify" + parameters;
    benchmark::RegisterBenchmark(verify_name.c_str(), [&ac, n, I](benchmark::State& state)
    {
        auto random = crypto12381::create_random_engine("seed");
        const auto keys = ac.keygen(n, random);
        const auto& [sk, pk] = keys;
        const auto attr = ac.generate_attributes(pk, n, random);
        const auto [usk, upk] = ac.user_keygen(pk, random);
        const auto sig = ac.issue(keys, upk, attr, random);

        constexpr std::string_view m = "anonymous credential benchmark";
        const auto pres_info = ac.pres(m, attr, sig, I, usk, pk, random);
        if(not ac.verify(m, attr, I, pres_info, pk))
        {
            state.SkipWithError("verification failed");
            return;
        }

        for(auto _ : state)
        {
            auto valid = ac.verify(m, attr, I, pres_info, pk);
            benchmark::DoNotOptimize(valid);
        }
    })->Unit(benchmark::kMicrosecond);
}

template<anonymous_credential...AC>
void register_experiment_1(const BenchmarkConfig& config, std::span<const size_t> indexes, const AC&...ac)
{
    const auto& experiment = config.experiment1;
    const auto disclosed_indexes = indexes.first(experiment.n_disclosed);

    for(size_t sample = 0uz; sample < experiment.samples; ++sample)
    {
        const auto attribute_count = experiment.first + experiment.interval * sample;
        (register_scheme_benchmarks("experiment1", ac, attribute_count, disclosed_indexes), ...);
    }
}

template<anonymous_credential...AC>
void register_experiment_2(const BenchmarkConfig& config, std::span<const size_t> indexes, const AC&...ac)
{
    const auto& experiment = config.experiment2;

    for(size_t sample = 0uz; sample < experiment.samples; ++sample)
    {
        const auto disclosed_count = experiment.first + experiment.interval * sample;
        const auto disclosed_indexes = indexes.first(disclosed_count);
        (register_scheme_benchmarks("experiment2", ac, experiment.n_attributes, disclosed_indexes), ...);
    }
}

template<anonymous_credential...AC>
void run_benchmarks(const BenchmarkConfig& config, const AC&...ac)
{
    const auto& [config1, config2] = config;
    const auto n_attributes_max = std::max(
        config1.first + config1.interval * (config1.samples - 1uz), 
        config2.n_attributes
    );
    std::vector<size_t> indexes(n_attributes_max);
    std::iota(indexes.begin(), indexes.end(), 0uz);

    register_experiment_1(config, indexes, ac...);
    register_experiment_2(config, indexes, ac...);
    benchmark::RunSpecifiedBenchmarks();
}

cxxopts::Options make_options(BenchmarkConfig& config)
{
    cxxopts::Options options{ "benchmark", "Anonymous credential benchmarks" };
    const auto with_default = [](auto& value)
    {
        return cxxopts::value(value)->default_value(std::to_string(value));
    };

    options.add_options("General")
        ("help", "Print help");

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

    return options;
}

int main(int argc, char* argv[])
{
    benchmark::MaybeReenterWithoutASLR(argc, argv);
    benchmark::Initialize(&argc, argv, []()
    {
        BenchmarkConfig config;
        const auto options = make_options(config);
        std::cout << options.help() << '\n';
        benchmark::PrintDefaultHelp();
    });

    try
    {
        BenchmarkConfig config;
        auto options = make_options(config);
        options.parse(argc, argv);

        validate(config);

        run_benchmarks(config, ac::rps, ac::bbs, ac::monipoly, ac::our_scheme);
        benchmark::Shutdown();
        return 0;
    }
    catch(const std::exception& error)
    {
        benchmark::Shutdown();
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
