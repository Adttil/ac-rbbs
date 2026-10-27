#include <optional>

#include <crypto12381/crypto12381.hpp>
#include <rbbs_star.hpp>

namespace anonymous_credentials
{
    RBBSStar::Keys RBBSStar::keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto h = random-select_in<*G1>;
        auto u = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto x = random-select_in<*Zp>;
        auto y = random-select_in<*Zp>;
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

        std::optional yn{ y };
        for(size_t i = 0uz; i < n; ++i)
        {
            const auto& power = *yn;
            keys.pk.Y[n + i + 2uz] = serialize(g^power);
            yn.emplace((power * y).normalize());
        }

        auto y_inv = inverse(y);
        yn.emplace((y_inv * y_inv).normalize());
        for(size_t i = 0uz; i < n; ++i)
        {
            const auto& power = *yn;
            keys.pk.Y[n - i - 1uz] = serialize(g^power);
            keys.pk.tilde_Y[n - 1uz - i] = serialize(tilde_g^power);
            yn.emplace((power * y_inv).normalize());
        }

        return keys;
    }
}
