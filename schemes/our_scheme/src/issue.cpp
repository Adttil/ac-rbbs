#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    OurScheme::Signature OurScheme::issue(
        const Keys& keys,
        const UserPublicKey& upk,
        std::span<const serialized_field<Zp>> attr,
        RandomEngine& random
    )
    {
        auto&&[sk, pk] = keys;
        auto [x, y] = parse<Zp^2>(sk);
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto Z = parse<G1>(upk);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();

        auto w = random-select_in<*Zp>;
        auto C = h * Z * Y[n + 1uz] * Π[n](Y[n + i + 2uz]^hash(a[i]).to(Zp));
        auto A = C^inverse(x + w);

        return serialize(A, C, w);
    }
}
