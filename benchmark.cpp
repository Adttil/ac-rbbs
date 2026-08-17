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
    const typename AC::PresProof& proof
)
{
    { ac.name() } -> std::same_as<std::string_view>;
    { ac.keygen(n, random) } -> std::same_as<typename AC::Keys>;
    { ac.user_keygen(pk, random) } -> std::same_as<typename AC::UserKeys>;
    { ac.generate_attributes(pk, n, random) } -> std::same_as<std::vector<crypto12381::serialized_field<crypto12381::Zp>>>;
    { ac.issue(keys, upk, attr, random) } -> std::same_as<typename AC::Signature>;
    { ac.pres(usk, attr, sig, I, m, pk, random) } -> std::same_as<typename AC::PresProof>;
    { ac.verify(attr, I, m, proof, pk) } -> std::same_as<bool>;
};

template<typename AC>
concept cacheable_anonymous_credential = anonymous_credential<AC> && requires(
    const AC& ac,
    crypto12381::RandomEngine& random,
    const typename AC::PublicKey& pk,
    const typename AC::UserSecretKey& usk,
    std::span<const crypto12381::serialized_field<crypto12381::Zp>> attr,
    std::span<const size_t> I,
    std::string_view m,
    const typename AC::Signature& sig,
    const typename AC::PresCache& cache
)
{
    { ac.preprocess(usk, attr, sig, I, pk) } -> std::same_as<typename AC::PresCache>;
    { ac.pres(usk, attr, sig, I, cache, m, pk, random) } -> std::same_as<typename AC::PresProof>;
};

struct BenchmarkConfig
{
    size_t attributes_first = 10uz;
    size_t attributes_interval = 10uz;
    size_t attributes_samples = 10uz;
    size_t disclosed_first = 1uz;
    size_t disclosed_interval = 1uz;
    size_t disclosed_samples = 10uz;
};

void validate(const BenchmarkConfig& config)
{
    if(config.attributes_samples == 0uz || config.disclosed_samples == 0uz)
    {
        throw std::invalid_argument{ "sample counts must be positive" };
    }
    if(config.attributes_first == 0uz)
    {
        throw std::invalid_argument{ "total attribute counts must be positive" };
    }

    const auto disclosed_last = config.disclosed_first
        + config.disclosed_interval * (config.disclosed_samples - 1uz);
    if(disclosed_last > config.attributes_first)
    {
        throw std::invalid_argument{ "disclosed attribute count exceeds the first total attribute count" };
    }
}

template<anonymous_credential AC>
void register_scheme_benchmarks(
    const AC& ac,
    size_t n,
    std::span<const size_t> I
)
{
    const auto prefix = std::string{ ac.name() };
    const auto parameters = "/attributes:" + std::to_string(n) + "/disclosed:" + std::to_string(I.size());

    const auto pres_name = prefix + "/pres" + parameters;
    benchmark::RegisterBenchmark(pres_name.c_str(), [=, &ac](benchmark::State& state)
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
            auto proof = ac.pres(usk, attr, sig, I, m, pk, random);
            benchmark::DoNotOptimize(proof);
        }
    })->Unit(benchmark::kMicrosecond);

    if constexpr(cacheable_anonymous_credential<AC>)
    {
        const auto preprocess_name = prefix + "/preprocess" + parameters;
        benchmark::RegisterBenchmark(preprocess_name.c_str(), [=, &ac](benchmark::State& state)
        {
            auto random = crypto12381::create_random_engine("seed");
            const auto keys = ac.keygen(n, random);
            const auto& [sk, pk] = keys;
            const auto attr = ac.generate_attributes(pk, n, random);
            const auto [usk, upk] = ac.user_keygen(pk, random);
            const auto sig = ac.issue(keys, upk, attr, random);

            for(auto _ : state)
            {
                auto cache = ac.preprocess(usk, attr, sig, I, pk);
                benchmark::DoNotOptimize(cache);
            }
        })->Unit(benchmark::kMicrosecond);

        const auto pres_with_cache_name = prefix + "/pres_with_cache" + parameters;
        benchmark::RegisterBenchmark(pres_with_cache_name.c_str(), [=, &ac](benchmark::State& state)
        {
            auto random = crypto12381::create_random_engine("seed");
            const auto keys = ac.keygen(n, random);
            const auto& [sk, pk] = keys;
            const auto attr = ac.generate_attributes(pk, n, random);
            const auto [usk, upk] = ac.user_keygen(pk, random);
            const auto sig = ac.issue(keys, upk, attr, random);
            const auto cache = ac.preprocess(usk, attr, sig, I, pk);

            constexpr std::string_view m = "anonymous credential benchmark";
            const auto proof = ac.pres(usk, attr, sig, I, cache, m, pk, random);
            if(not ac.verify(attr, I, m, proof, pk))
            {
                state.SkipWithError("verification failed");
                return;
            }

            for(auto _ : state)
            {
                auto result = ac.pres(usk, attr, sig, I, cache, m, pk, random);
                benchmark::DoNotOptimize(result);
            }
        })->Unit(benchmark::kMicrosecond);
    }

    const auto verify_name = prefix + "/verify" + parameters;
    benchmark::RegisterBenchmark(verify_name.c_str(), [=, &ac](benchmark::State& state)
    {
        auto random = crypto12381::create_random_engine("seed");
        const auto keys = ac.keygen(n, random);
        const auto& [sk, pk] = keys;
        const auto attr = ac.generate_attributes(pk, n, random);
        const auto [usk, upk] = ac.user_keygen(pk, random);
        const auto sig = ac.issue(keys, upk, attr, random);

        constexpr std::string_view m = "anonymous credential benchmark";
        const auto proof = ac.pres(usk, attr, sig, I, m, pk, random);
        if(not ac.verify(attr, I, m, proof, pk))
        {
            state.SkipWithError("verification failed");
            return;
        }

        for(auto _ : state)
        {
            auto valid = ac.verify(attr, I, m, proof, pk);
            benchmark::DoNotOptimize(valid);
        }
    })->Unit(benchmark::kMicrosecond);
}

template<anonymous_credential...AC>
void run_benchmarks(const BenchmarkConfig& config, const AC&...ac)
{
    const auto attributes_max = config.attributes_first
        + config.attributes_interval * (config.attributes_samples - 1uz);
    std::vector<size_t> indexes(attributes_max);
    std::iota(indexes.begin(), indexes.end(), 0uz);
    const auto indexes_span = std::span<const size_t>{ indexes };

    for(size_t attributes_sample = 0uz; attributes_sample < config.attributes_samples; ++attributes_sample)
    {
        const auto attribute_count = config.attributes_first
            + config.attributes_interval * attributes_sample;
        for(size_t disclosed_sample = 0uz; disclosed_sample < config.disclosed_samples; ++disclosed_sample)
        {
            const auto disclosed_count = config.disclosed_first
                + config.disclosed_interval * disclosed_sample;
            const auto disclosed_indexes = indexes_span.first(disclosed_count);
            (register_scheme_benchmarks(ac, attribute_count, disclosed_indexes), ...);
        }
    }
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

    options.add_options("Sampling")
        ("total-start", "First total attribute count", with_default(config.attributes_first))
        ("total-step", "Total attribute sampling interval", with_default(config.attributes_interval))
        ("total-samples", "Number of total attribute samples", with_default(config.attributes_samples))
        ("disclosed-start", "First disclosed attribute count", with_default(config.disclosed_first))
        ("disclosed-step", "Disclosed attribute sampling interval", with_default(config.disclosed_interval))
        ("disclosed-samples", "Number of disclosed attribute samples", with_default(config.disclosed_samples));

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
