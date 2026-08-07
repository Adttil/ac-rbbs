#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    MoniPoly::PresInfo MoniPoly::pres(
        std::string_view m,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        const RedactCache& redact_cache,
        const UserSecretKey& usk,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [v, t, s, o] = parse<G1|Zp^3>(sig);
        auto a = parse<Zp>(attr);
        auto z = parse<Zp>(usk);
        auto W0 = parse<G1>(redact_cache);
        auto [b, c, u, tiled_g, tiled_X] = parse<G1^3|G2^2>(pk.fixed_part);
        auto [r, y, tilde_r, tilde_y, tilde_ty, tilde_s, tilde_theta] = random-select_in<*Zp^7>;

        auto r_over_y = (r * inverse(y)).normalize();
        auto v_ = v^r_over_y;

        auto W = W0^r;
        auto V = v_^tilde_y;
        auto Y = (b^tilde_s) * (c^tilde_r) * (v_^tilde_ty);
        auto theta = (r * z).normalize();
        auto D = u^theta;
        auto T_z = u^tilde_theta;

        auto e = hash(m, pk.fixed_part, v_, V, W, Y, D, T_z, I, a[i](i.in(I))).to(Zp);
        auto s_r = (tilde_r + e * r).normalize();
        auto s_y = (tilde_y + e * y).normalize();
        auto s_ty = (tilde_ty - e * t * y).normalize();
        auto s_s = (tilde_s + e * s * r).normalize();
        auto s_theta = (tilde_theta + e * theta).normalize();

        return serialize(v_, V, W, Y, D, T_z, s_r, s_y, s_ty, s_s, s_theta);
    }
}
