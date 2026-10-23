#include <crypto12381/crypto12381.hpp>
#include <rbbs.hpp>

namespace anonymous_credentials
{
    RBBS::Signature RBBS::issue(
        const Keys& keys,
        const UserPublicKey& upk,
        std::span<const serialized_field<Zp>> attr,
        RandomEngine& random
    )
    {
        auto&&[sk, pk] = keys;
        auto x = parse<Zp>(sk);
        auto h = parse<G1>(std::span{ pk.fixed_part }.first<serialized_size<G1>>());
        auto Z = parse<G1>(upk);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();

        auto w = [&](){
            for(;;)
            {
                auto candidate = random-select_in<Zp>;
                if(x + candidate != make_Zp(0u)) return candidate;
            }
        }();
        auto C = h * Z * Y[n + 1uz] * Π[n](Y[n + i + 2uz]^a[i]);
        auto A = C^inverse(x + w);

        return serialize(A, C, w);
    }
}
