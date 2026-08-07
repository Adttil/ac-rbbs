#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::PresInfo BBS::pres(
        std::string_view m,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        const RedactCache&,
        const UserSecretKey& usk,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });

        auto C_I = g * Π[i.in(I)](Y[i + 1uz]^a[i]);
        auto r = random-select_in<Zp>;
        auto A_ = A^r;
        auto B_ = (C^r) * (A_^-w);

        auto [alpha, beta, gamma] = random-select_in<Zp^3>;
        auto u_random = random-select_in<Zp>(J.size()) | materialize;
        auto U = (C_I^alpha) * (A_^beta) * (Y[0]^gamma) * Π[j.in[J.size()]](Y[J[j] + 1uz]^u_random[j]);

        auto c = hash(m, A_, B_, U).to(Zp);
        auto s = alpha + r*c;
        auto t = beta + -w*c;
        auto s_z = gamma + r*c*z;
        auto uj = u_random[j] + r*c*a[J[j]];

        return {
            .fixed_part = serialize(A_, B_, U, s, t, s_z),
            .u = serialize(uj) (j.in[J.size()])
        };
    }
}
