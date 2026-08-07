#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::Keys BBS::keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto x = random-select_in<Zp>;
        auto tilde_X = tilde_g^x;
        auto Y = random-select_in<*G1>(n + 1uz);

        return {
            .sk = serialize(x),
            .pk = {
                .fixed_part = serialize(g, tilde_g, tilde_X),
                .Y = serialize(Y[i]) (i.in[n + 1uz])
            }
        };
    }
}
