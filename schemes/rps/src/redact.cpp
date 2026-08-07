#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::RedactCache RPS::redact(
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        const UserSecretKey&,
        std::span<const size_t> I,
        const PublicKey& pk
    )
    {
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        auto [h, sigma, tilde_M] = parse<G1^2|G2>(sig);
        auto tilde_H = tilde_M / Π[i.in(I)](tilde_Y[i]^a[i]);
        return serialize(tilde_H);
    }
}
