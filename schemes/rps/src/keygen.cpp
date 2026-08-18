#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::Keys RPS::keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto [x, y] = random-select_in<Zp^2>;
        auto tilde_X = tilde_g^x;

        Keys keys{
            .sk = serialize(x),
            .pk = {
                .fixed_part = serialize(g, tilde_g, tilde_X),
                .Y{ 2uz * n + 1uz },
                .tilde_Y{ n + 1uz }
            }
        };

        [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i >= 2uz * n + 1uz)
            {
               return;
            }
            if(i <= n)
            {
                keys.pk.tilde_Y[i] = serialize(tilde_g^yn);
            }
            if(i == n + 1uz)
            {
                keys.pk.Y[i] = serialize(g);
            }
            else
            {
                keys.pk.Y[i] = serialize(g^yn);
            }
            self(yn * y, i + 1uz);
        }(y);

        return keys;
    }
}
