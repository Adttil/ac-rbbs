#include <stdexcept>

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
        auto A = parse<G1>(pk.a) | materialize;
        auto o = random-select_in<*Zp>;

        auto k = encode(a, o);

        auto C = Π[k.size()](A[i]^k[i]);
        auto s1 = random-select_in<*Zp>;
        auto M = C * Z * (b^s1);

        auto m_tilde = random-select_in<Zp>(k.size()) | materialize;
        auto s1_tilde = random-select_in<*Zp>;
        auto R = Π[k.size()](A[i]^m_tilde[i]) * (b^s1_tilde);

        auto e = hash(pk.fixed_part, pk.a, pk.tilde_a, upk, M, R).to(Zp);
        auto m_hat = (m_tilde[i] + e * k[i]) (i.in[k.size()]);
        auto s1_hat = (s1_tilde + e * s1);

        auto L = Π[k.size()](A[i]^m_hat[i]) * (b^s1_hat);
        if(L != R * ((M / Z)^e))
        {
            throw std::runtime_error{ "MoniPoly blind issuing initialization proof failed" };
        }

        auto t = random-select_in<*Zp>;
        auto s2 = random-select_in<*Zp>;
        auto v = (M * (b^s2) * c)^inverse(x + t);
        auto s = s1 + s2;

        if(pair(v, tiled_X * (tiled_g^t)) != pair(C * Z * (b^s) * c, tiled_g))
        {
            throw std::runtime_error{ "MoniPoly issuer returned an invalid SDH-CL signature" };
        }

        return serialize(v, t, s, o);
    }
}
