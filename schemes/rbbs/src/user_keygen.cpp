#include <crypto12381/crypto12381.hpp>
#include <rbbs.hpp>

namespace anonymous_credentials
{
    RBBS::UserKeys RBBS::user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto u = parse<G1>(std::span{ pk.fixed_part }.subspan<serialized_size<G1>, serialized_size<G1>>());
        auto z = random-select_in<*Zp>;
        return {
            .usk = serialize(z),
            .upk = serialize(u^z)
        };
    }
}
