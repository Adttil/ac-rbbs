#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    auto encode(const auto& a, const auto& o)
    {
        return std::ranges::fold_left(
            sequence(a.size() + 1uz),
            std::views::single(make_Zp(1u)) | materialize,
            [&](auto k, size_t j)
            {
                auto root = j < a.size() ? a[j] : o;
                const size_t n = k.size();
                return sequence(n + 1uz)
                    | transform([k = std::move(k), root, n](size_t i)
                    {
                        if(i == 0uz)
                        {
                            return (k[0] * root).normalize();
                        }
                        if(i == n)
                        {
                            return k[n - 1uz];
                        }
                        return (k[i] * root + k[i - 1uz]).normalize();
                    })
                    | materialize;
            }
        );
    }

    MoniPoly::Signature MoniPoly::issue(
        const Keys& keys,
        const UserPublicKey& upk,
        std::span<const serialized_field<Zp>> attr,
        RandomEngine& random
    )
    {
        auto&&[sk, pk] = keys;
        auto [x, x_prime] = parse<Zp^2>(sk);
        auto [b, c, u, tiled_g, tiled_X] = parse<G1^3|G2^2>(pk.fixed_part);
        auto Z = parse<G1>(upk);
        auto a = parse<Zp>(attr);
        auto A = parse<G1>(pk.a);
        auto o = random-select_in<*Zp>;

        auto k = encode(a, o);

        auto C = Π[k.size()](A[i]^k[i]);
        auto t = random-select_in<*Zp>;
        auto s = random-select_in<*Zp>;
        auto v = (C * Z * (b^s) * c)^inverse(x + t);

        return serialize(v, t, s, o);
    }
}
