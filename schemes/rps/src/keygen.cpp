#include <optional>

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

        // Zp values are non-assignable; emplace advances the power without recursion.
        std::optional yn{ y };
        for(size_t i = 0uz; i < 2uz * n + 1uz; ++i)
        {
            const auto& power = *yn;
            if(i <= n)
            {
                keys.pk.tilde_Y[i] = serialize(tilde_g^power);
            }
            if(i == n + 1uz)
            {
                keys.pk.Y[i] = serialize(g);
            }
            else
            {
                keys.pk.Y[i] = serialize(g^power);
            }
            yn.emplace((power * y).normalize());
        }

        return keys;
    }
}
