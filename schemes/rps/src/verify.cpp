#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    bool RPS::verify(
        std::span<const serialized_field<Zp>> attr,
        std::span<const size_t> indexes,
        std::string_view,
        const PresProof& proof,
        const PublicKey& pk
    )
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        auto I = indexes | algebraic;
        auto [sigma1_, sigma2_, sigma3_, C, tilde_sigma_, c0, s0] = parse<G1^4|G2|Zp^2>(proof);

        auto C0 = (sigma1_^s0) * (C^c0);
        if(c0 != hash(sigma1_, C, C0).to(Zp))
        {
            return false;
        }

        std::vector<size_t> I_plus(indexes.begin(), indexes.end());
        I_plus.push_back(n);
        auto Ip = I_plus | algebraic;

        auto q = hash(sigma1_, sigma2_, tilde_sigma_, indexes, a[j](j.in(I)), i)
            .to(Zp) (i.in(Ip)) | materialize;

        return
            pair(sigma1_, tilde_X * tilde_sigma_ * Π[i.in(I)](tilde_Y[i]^a[i])) * pair(C, tilde_Y[n])
            == pair(sigma2_, tilde_g)
            &&
            pair(sigma3_, tilde_g)
            == pair(Π[i.in[I_plus.size()]](Y[n - Ip[i]]^q[i]), tilde_sigma_);
    }
}
