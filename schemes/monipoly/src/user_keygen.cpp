#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    MoniPoly::UserKeys MoniPoly::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto [b, c, u, tiled_g, tiled_X] = parse<G1^3|G2^2>(pk.fixed_part);
        auto z = random-select_in<*Zp>;
        return {
            .usk = serialize(z),
            .upk = serialize(u^z)
        };
    }
}
