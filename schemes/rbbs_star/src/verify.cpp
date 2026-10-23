#include <crypto12381/crypto12381.hpp>
#include <rbbs_star.hpp>

namespace anonymous_credentials
{
    bool RBBSStar::verify(
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
        auto [A_, B_, C_J_, D_, c, s_r, s_w, s_z, s_t] = parse<G1^4|Zp^5>(proof);
        if(proof[0] == 0)
        {
            return false;
        }

        auto C_I = h * Π[i.in(I)](Y[n + i + 2uz]^a[i]);
        auto U = (u^s_z) * (C_I^s_r) * (A_^s_w) * (Y[n + 1uz]^s_t) * (B_^-c);
        auto q = hash(C_I, C_J_, indexes, i).to(Zp) (i.in(I));

        return
            c == hash(m, indexes, C_I, A_, B_, C_J_, D_, U).to(Zp)
            &&
            pair(A_, tilde_X) * pair(C_J_^c, Π[i.in[I.size()]](tilde_Y[n - 1uz - I[i]]^q[i]))
                == pair(B_ * C_J_ * (D_^c), tilde_g);
    }
}
