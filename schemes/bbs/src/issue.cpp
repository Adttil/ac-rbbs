#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::Signature BBS::issue(
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
        auto a = parse<Zp>(attr);
        const size_t n = a.size();

        auto w = random-select_in<*Zp>;
        auto C = g * Z * Π[n](Y[i + 1uz]^a[i]);
        auto A = C^inverse(x + w);

        return serialize(A, C, w);
    }
}
