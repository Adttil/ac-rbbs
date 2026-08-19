#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::PresProof BBS::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> I,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        const auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        const auto Y = parse<G1>(pk.Y) | materialize;
        const auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        const auto [A, C, w] = parse<G1^2|Zp>(sig);
        const auto z = parse<Zp>(usk);
        const auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });

        const auto C_I = g * Π[i.in(I)](Y[i + 1uz]^a[i]);
        const auto r = random-select_in<Zp>;
        const auto A_ = (A^r).G1_point();
        const auto B_ = (C^r) * (A_^-w);

        const auto [alpha, beta, gamma] = random-select_in<Zp^3>;
        const auto u_random = random-select_in<Zp>(J.size()) | materialize;
        const auto U = (C_I^alpha) * (A_^beta) * (Y[0]^gamma) * Π[j.in[J.size()]](Y[J[j] + 1uz]^u_random[j]);

        const auto c = hash(m, A_, B_, U).to(Zp);
        const auto rc = r*c;
        const auto s = alpha + rc;
        const auto t = beta + -w*c;
        const auto s_z = gamma + rc*z;
        const auto uj = u_random[j] + rc*a[J[j]];

        return {
            .fixed_part = serialize(A_, B_, U, s, t, s_z),
            .u = serialize(uj) (j.in[J.size()])
        };
    }
}
