#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    bool OurScheme::verify(
        std::span<const serialized_field<Zp>> attr,
        std::span<const size_t> indexes,
        std::string_view m,
        const PresProof& proof,
        const PublicKey& pk
    )
    {
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        auto I = indexes | algebraic;
        auto [A_, B_, C_J_, D_, U, s_r, s_w, s_z] = parse<G1^5|Zp^3>(proof);

        auto c = hash(m, A_, B_, C_J_, D_, U).to(Zp);
        auto C_I = h * Π[i.in(I)](Y[n + i + 2uz]^a[i]);
        auto q = hash(C_I, i).to(Zp) (i.in(I));
        auto Q_I = Π[i.in[I.size()]](tilde_Y[n - 1uz - I[i]]^q[i]);

        return
            pair(A_, tilde_X) * pair(C_J_^c, Q_I) == pair(B_ * C_J_ * (D_^c), tilde_g)
            &&
            U * (B_^c) == (u^s_z) * (C_I^s_r) * (A_^s_w);
    }
}
