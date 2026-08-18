#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::UserKeys RPS::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto Y = parse<G1>(pk.Y);
        const size_t n = pk.tilde_Y.size() - 1uz;
        auto usk = random-select_in<*Zp>;
        return {
            .usk = serialize(usk),
            .upk = serialize(Y[n]^usk)
        };
    }
}
