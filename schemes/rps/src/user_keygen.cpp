#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::UserKeys RPS::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto usk = random-select_in<*Zp>;
        return {
            .usk = serialize(usk),
            .upk = serialize(g^usk)
        };
    }
}
