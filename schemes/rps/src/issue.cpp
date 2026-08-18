#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::Signature RPS::issue(
        const Keys& keys,
        const UserPublicKey& upk,
        std::span<const serialized_field<Zp>> attr,
        RandomEngine& random
    )
    {
        auto&&[sk, pk] = keys;
        auto x = parse<Zp>(sk);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Z = parse<G1>(upk);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();

        auto alpha = random-select_in<*Zp>;
        auto h = g^alpha;

        auto sigma = (h^x) * ((Z * Π[n](Y[i]^a[i]))^alpha);
        auto tilde_M = Π[n](tilde_Y[i]^a[i]);

        return serialize(h, sigma, tilde_M);
    }
}
