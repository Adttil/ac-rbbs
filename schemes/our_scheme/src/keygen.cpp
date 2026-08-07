#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    OurScheme::Keys OurScheme::keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto h = random-select_in<*G1>;
        auto u = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto [x, y] = random-select_in<Zp^2>;
        auto tilde_X = tilde_g^x;

        Keys keys{
            .sk = serialize(x, y),
            .pk = {
                .fixed_part = serialize(h, u, tilde_g, tilde_X),
                .Y{ 2uz * n + 2uz },
                .tilde_Y{ n }
            }
        };

        keys.pk.Y[n] = serialize(g);
        keys.pk.Y[n + 1uz] = serialize(g);

        [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i >= n)
            {
                return;
            }
            keys.pk.Y[n + i + 2uz] = serialize(g^yn);
            self(yn * y, i + 1uz);
        }(y);

        auto y_inv = inverse(y);
        [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i >= n)
            {
                return;
            }
            keys.pk.Y[n - i - 1uz] = serialize(g^yn);
            keys.pk.tilde_Y[n - 1uz - i] = serialize(tilde_g^yn);
            self(yn * y_inv, i + 1uz);
        }(y_inv * y_inv);

        return keys;
    }
}
