#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    bool BBS::verify(
        std::span<const serialized_field<Zp>> attr,
        std::span<const size_t> I,
        const PresProof& proof,
        const PublicKey& pk
    )
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        auto [A_, B_, c, s, t, s_z] = parse<G1^2|Zp^4>(proof.fixed_part);
        auto u = parse<Zp>(proof.u);
        auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });

        auto C_I = g * Π[i.in(I)](Y[i + 1uz]^a[i]);
        auto U = (C_I^s) * (A_^t) * (Y[0]^s_z)
            * Π[j.in[J.size()]](Y[J[j] + 1uz]^u[j]) * (B_^-c);

        return
            pair(A_, tilde_X) == pair(B_, tilde_g)
            &&
            c == hash(I, C_I, A_, B_, U).to(Zp);
    }
}
