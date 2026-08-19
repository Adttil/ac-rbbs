#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    auto encode(const auto& a, std::span<const size_t> I)
    {
            return std::ranges::fold_left(
                I,
                std::views::single(make_Zp(1u)) | materialize,
                [&](auto k, size_t index)
                {
                    auto root = a[index];
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

    bool MoniPoly::verify(
        std::span<const serialized_field<Zp>> attr,
        std::span<const size_t> I,
        std::string_view m,
        const PresProof& proof,
        const PublicKey& pk
    )
    {
        auto a = parse<Zp>(attr);
        auto k_I = encode(a, I);
        auto tilde_a = parse<G2>(pk.tilde_a);
        auto tilde_A = Π[k_I.size()](tilde_a[i]^k_I[i]);

        auto [b, c, u, tilde_g, tilde_X] = parse<G1^3|G2^2>(pk.fixed_part);
        auto [v_, V, W, Y, D, T_z, s_r, s_y, s_ty, s_s, s_theta] = parse<G1^6|Zp^5>(proof);
        auto e = hash(m, pk.fixed_part, v_, V, W, Y, D, T_z, I, a[i](i.in(I))).to(Zp);

        auto D_e = (D^e).G1_point();
        auto L = (D_e * (b^s_s) * (c^s_r) * (v_^s_ty)) / Y;
        auto R = (v_^s_y) / V;

        return
            pair(W^e, tilde_A) * pair(L, tilde_g) == pair(R, tilde_X)
            &&
            (u^s_theta) == T_z * D_e;
    }
}
