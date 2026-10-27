#include <optional>

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

        std::optional x_power{ make_Zp(1u) };
        for(size_t i = 0uz; i < n + 2uz; ++i)
        {
            const auto& power = *x_power;
            keys.pk.a[i] = serialize(a0^power);
            keys.pk.tilde_a[i] = serialize(tiled_g^power);
            x_power.emplace((power * x_prime).normalize());
        }

        return keys;
    }
}
