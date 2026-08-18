#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    MoniPoly::Keys MoniPoly::keygen(size_t n, RandomEngine& random)
    {
        auto a0 = random-select_in<*G1>;
        auto [b, c, u] = random-select_in<*G1^3>;
        auto tiled_g = random-select_in<*G2>;
        auto [x, x_prime] = random-select_in<*Zp^2>;
        auto tiled_X = tiled_g^x;

        Keys keys{
            .sk = serialize(x, x_prime),
            .pk = {
                .fixed_part = serialize(b, c, u, tiled_g, tiled_X),
                .a{ n + 2uz },
                .tilde_a{ n + 2uz }
            }
        };

        [&](this auto&& self, auto&& x_power, size_t i = 0uz) -> void
        {
            if(i >= n + 2uz)
            {
                return;
            }

            keys.pk.a[i] = serialize(a0^x_power);
            keys.pk.tilde_a[i] = serialize(tiled_g^x_power);
            self(x_power * x_prime, i + 1uz);
        }(make_Zp(1u));

        return keys;
    }
}
