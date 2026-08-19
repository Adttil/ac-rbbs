#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    namespace
    {
        auto encode(const auto& a, const auto& o, std::span<const size_t> I)
        {
            const size_t n = a.size();
            auto roots = sequence(n + 1uz) | filter([&](size_t i){ return i == n || not std::ranges::contains(I, i); });
            return std::ranges::fold_left(
                roots,
                std::views::single(make_Zp(1u)) | materialize,
                [&](auto k, size_t j)
                {
                    auto root = j < n ? a[j] : o;
                    const size_t degree = k.size();
                    return sequence(degree + 1uz)
                        | transform([k = std::move(k), root, degree](size_t i)
                        {
                            if(i == 0uz)
                            {
                                return (k[0] * root).normalize();
                            }
                            if(i == degree)
                            {
                                return k[degree - 1uz];
                            }
                            return (k[i] * root + k[i - 1uz]).normalize();
                        })
                        | materialize;
                }
            );
        }

        auto preprocess_impl(
            const auto& a,
            const auto& o,
            std::span<const size_t> I,
            const auto& A
        )
        {
            auto k = encode(a, o, I);
            return Π[k.size()](A[i]^k[i]);
        }

        MoniPoly::PresProof pres_impl(
            std::string_view m,
            const auto& a,
            std::span<const size_t> I,
            const auto& v,
            const auto& t,
            const auto& s,
            const auto& W0,
            const auto& z,
            const auto& b,
            const auto& c,
            const auto& u,
            const auto& fixed_part,
            RandomEngine& random
        )
        {
            auto [r, y, tilde_r, tilde_y, tilde_ty, tilde_s, tilde_theta] = random-select_in<*Zp^7>;

            auto r_over_y = (r * inverse(y));
            auto v_ = (v^r_over_y).G1_point();

            auto W = (W0^r).G1_point();
            auto V = (v_^tilde_y).G1_point();
            auto Y = (b^tilde_s) * (c^tilde_r) * (v_^tilde_ty);
            auto theta = (r * z);
            auto D = (u^theta).G1_point();
            auto T_z = (u^tilde_theta).G1_point();

            auto e = hash(m, fixed_part, v_, V, W, Y, D, T_z, I, a[i](i.in(I))).to(Zp);
            auto s_r = (tilde_r + e * r);
            auto s_y = (tilde_y + e * y);
            auto s_ty = (tilde_ty - e * t * y);
            auto s_s = (tilde_s + e * s * r);
            auto s_theta = (tilde_theta + e * theta);

            return serialize(v_, V, W, Y, D, T_z, s_r, s_y, s_ty, s_s, s_theta);
        }
    }

    MoniPoly::PresProof MoniPoly::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [v, t, s, o] = parse<G1|Zp^3>(sig);
        auto a = parse<Zp>(attr);
        auto z = parse<Zp>(usk);
        auto A = parse<G1>(pk.a);
        auto W0 = preprocess_impl(a, o, I, A);
        auto [b, c, u, tiled_g, tiled_X] = parse<G1^3|G2^2>(pk.fixed_part);

        return pres_impl(m, a, I, v, t, s, W0, z, b, c, u, pk.fixed_part, random);
    }

    MoniPoly::PresCache MoniPoly::preprocess(
        const UserSecretKey&,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        const PublicKey& pk
    )
    {
        auto [v, t, s, o] = parse<G1|Zp^3>(sig);
        auto a = parse<Zp>(attr);
        auto A = parse<G1>(pk.a);
        auto W0 = preprocess_impl(a, o, I, A);
        return serialize(W0);
    }

    MoniPoly::PresProof MoniPoly::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        const PresCache& cache,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [v, t, s, o] = parse<G1|Zp^3>(sig);
        auto a = parse<Zp>(attr);
        auto z = parse<Zp>(usk);
        auto W0 = parse<G1>(cache);
        auto [b, c, u, tiled_g, tiled_X] = parse<G1^3|G2^2>(pk.fixed_part);

        return pres_impl(m, a, I, v, t, s, W0, z, b, c, u, pk.fixed_part, random);
    }
}
