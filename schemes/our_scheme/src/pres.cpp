#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    OurScheme::PresInfo OurScheme::pres(
        std::string_view m,
        std::span<const serialized_field<Zp>>,
        const Signature& sig,
        std::span<const size_t>,
        const RedactCache& redact_cache,
        const UserSecretKey& usk,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto [C_I, C_J, B, D] = parse<G1^4>(redact_cache);
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);

        auto r = random-select_in<Zp>;
        auto A_ = A^r;
        auto B_ = B^r;
        auto C_J_ = C_J^r;
        auto D_ = D^r;

        auto [alpha, beta, gamma] = random-select_in<Zp^3>;
        auto U = (u^gamma) * (C_I^alpha) * (A_^beta);

        auto c = hash(m, A_, B_, C_J_, D_, U).to(Zp);
        auto s_r = alpha + r*c;
        auto s_w = beta + -w*c;
        auto s_z = gamma + r*z*c;

        return serialize(A_, B_, C_J_, D_, U, s_r, s_w, s_z);
    }
}
