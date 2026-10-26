#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <random>
#include <set>
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
    const typename AC::Signature& sig,
    const typename AC::PresProof& proof
)
{
    { ac.name() } -> std::same_as<std::string_view>;
    { ac.keygen(n, random) } -> std::same_as<typename AC::Keys>;
    { ac.user_keygen(pk, random) } -> std::same_as<typename AC::UserKeys>;
    { ac.generate_attributes(pk, n, random) } -> std::same_as<std::vector<crypto12381::serialized_field<crypto12381::Zp>>>;
    { ac.issue(keys, upk, attr, random) } -> std::same_as<typename AC::Signature>;
    { ac.pres(usk, attr, sig, I, pk, random) } -> std::same_as<typename AC::PresProof>;
    { ac.verify(attr, I, proof, pk) } -> std::same_as<bool>;
};

struct BenchmarkConfig
{
    size_t attributes_first = 10uz;
    size_t attributes_interval = 10uz;
    size_t attributes_samples = 10uz;
    size_t disclosed_first = 1uz;
    size_t disclosed_interval = 1uz;
    size_t disclosed_samples = 10uz;
    size_t disclosure_sets = 64uz;
    std::uint64_t disclosure_seed = 0;
};

void validate(const BenchmarkConfig& config)
{
    if(config.attributes_samples == 0uz || config.disclosed_samples == 0uz || config.disclosure_sets == 0uz)
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

using DisclosureSets = std::vector<std::vector<size_t>>;

DisclosureSets make_disclosure_sets(size_t n, size_t m, size_t count, std::uint64_t seed)
{
    std::mt19937_64 random(seed);
    DisclosureSets sets;
    std::vector<size_t> indexes(m);
    std::iota(indexes.begin(), indexes.end(), 0uz);

    // Use all combinations if the population fits in the requested pool.
    for(;;)
    {
        sets.push_back(indexes);
        size_t position = m;
        while(position > 0uz && indexes[position - 1uz] == n - m + position - 1uz)
        {
            --position;
        }
        if(position == 0uz)
        {
            std::shuffle(sets.begin(), sets.end(), random);
            return sets;
        }
        if(sets.size() == count)
        {
            break;
        }
        ++indexes[position - 1uz];
        for(size_t i = position; i < m; ++i)
        {
            indexes[i] = indexes[i - 1uz] + 1uz;
        }
    }

    // A shuffled prefix is a uniform subset; reject duplicate subsets.
    sets.clear();
    std::set<std::vector<size_t>> seen;
    indexes.resize(n);
    std::iota(indexes.begin(), indexes.end(), 0uz);
    while(sets.size() < count)
    {
        std::shuffle(indexes.begin(), indexes.end(), random);
        std::vector<size_t> selected(indexes.begin(), indexes.begin() + m);
        std::ranges::sort(selected);
        if(seen.insert(selected).second)
        {
            sets.push_back(std::move(selected));
        }
    }
    return sets;
}

template<anonymous_credential AC>
void register_scheme_benchmarks(
    const AC& ac,
    size_t n,
    const DisclosureSets& disclosure_sets
)
{
    const auto prefix = std::string{ ac.name() };
    const auto parameters = "/attributes:" + std::to_string(n) + "/disclosed:" + std::to_string(disclosure_sets.front().size());

    const auto pres_name = prefix + "/pres" + parameters;
    benchmark::RegisterBenchmark(pres_name.c_str(), [&, n](benchmark::State& state)
    {
        auto random = crypto12381::create_random_engine("seed");
        const auto keys = ac.keygen(n, random);
        const auto& [sk, pk] = keys;
        const auto attr = ac.generate_attributes(pk, n, random);
        const auto [usk, upk] = ac.user_keygen(pk, random);
        const auto sig = ac.issue(keys, upk, attr, random);

        // Each complete traversal gives every disclosure set equal weight.
        while(state.KeepRunningBatch(disclosure_sets.size()))
        {
            for(const auto& I : disclosure_sets)
            {
                auto proof = ac.pres(usk, attr, sig, I, pk, random);
                benchmark::DoNotOptimize(proof);
            }
        }
        state.counters["disclosure_sets"] = static_cast<double>(disclosure_sets.size());
    })->Unit(benchmark::kMicrosecond);

    const auto verify_name = prefix + "/verify" + parameters;
    benchmark::RegisterBenchmark(verify_name.c_str(), [&, n](benchmark::State& state)
    {
        auto random = crypto12381::create_random_engine("seed");
        const auto keys = ac.keygen(n, random);
        const auto& [sk, pk] = keys;
        const auto attr = ac.generate_attributes(pk, n, random);
        const auto [usk, upk] = ac.user_keygen(pk, random);
        const auto sig = ac.issue(keys, upk, attr, random);

        std::vector<typename AC::PresProof> proofs;
        proofs.reserve(disclosure_sets.size());
        for(const auto& I : disclosure_sets)
        {
            proofs.push_back(ac.pres(usk, attr, sig, I, pk, random));
            if(not ac.verify(attr, I, proofs.back(), pk))
            {
                state.SkipWithError("verification failed");
                return;
            }
        }

        while(state.KeepRunningBatch(disclosure_sets.size()))
        {
            for(size_t i = 0uz; i < disclosure_sets.size(); ++i)
            {
                auto valid = ac.verify(attr, disclosure_sets[i], proofs[i], pk);
                benchmark::DoNotOptimize(valid);
            }
        }
        state.counters["disclosure_sets"] = static_cast<double>(disclosure_sets.size());
    })->Unit(benchmark::kMicrosecond);
}

template<anonymous_credential...AC>
void run_benchmarks(const BenchmarkConfig& config, const AC&...ac)
{
    benchmark::AddCustomContext("disclosure_sets_requested", std::to_string(config.disclosure_sets));
    benchmark::AddCustomContext("disclosure_seed", std::to_string(config.disclosure_seed));

    // Keep all pools alive and prevent reallocation while callbacks hold references.
    std::vector<DisclosureSets> disclosure_pools;
    disclosure_pools.reserve(config.attributes_samples * config.disclosed_samples);

    for(size_t attributes_sample = 0uz; attributes_sample < config.attributes_samples; ++attributes_sample)
    {
        const auto attribute_count = config.attributes_first
            + config.attributes_interval * attributes_sample;
        for(size_t disclosed_sample = 0uz; disclosed_sample < config.disclosed_samples; ++disclosed_sample)
        {
            const auto disclosed_count = config.disclosed_first
                + config.disclosed_interval * disclosed_sample;
            disclosure_pools.push_back(make_disclosure_sets(
                attribute_count, disclosed_count, config.disclosure_sets, config.disclosure_seed));
            const auto& disclosure_sets = disclosure_pools.back();
            (register_scheme_benchmarks(ac, attribute_count, disclosure_sets), ...);
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
        ("disclosed-samples", "Number of disclosed attribute samples", with_default(config.disclosed_samples))
        ("disclosure-sets", "Disclosure subsets per point (enumerate all if fewer exist)", with_default(config.disclosure_sets))
        ("disclosure-seed", "Seed for disclosure subset sampling", with_default(config.disclosure_seed));

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

        run_benchmarks(config, ac::rps, ac::bbs, ac::monipoly, ac::rbbs, ac::rbbs_star);
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
