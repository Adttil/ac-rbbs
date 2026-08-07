#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::UserKeys BBS::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto Y = parse<G1>(pk.Y);
        auto z = random-select_in<*Zp>;
        return {
            .usk = serialize(z),
            .upk = serialize(Y[0]^z)
        };
    }
}
