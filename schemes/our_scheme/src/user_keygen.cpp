#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    OurScheme::UserKeys OurScheme::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto z = random-select_in<*Zp>;
        return {
            .usk = serialize(z),
            .upk = serialize(u^z)
        };
    }
}
