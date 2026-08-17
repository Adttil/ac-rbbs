#include <optional>

#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    RPS::PresProof RPS::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> indexes,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [h, sigma, tilde_M] = parse<G1^2|G2>(sig);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto z = parse<Zp>(usk);
        
        auto I = indexes | algebraic;
        auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });
        
        std::vector<size_t> I_plus(indexes.begin(), indexes.end());
        I_plus.push_back(n);
        auto Ip = I_plus | algebraic;

        auto [r, t, rho] = random-select_in<Zp^3>;

        auto tilde_H = tilde_M / Π[i.in(I)](tilde_Y[i]^a[i]);
        auto sigma1_ = h^r;
        auto sigma2_ = (sigma^r) * (sigma1_^t);
        auto tilde_sigma_ = (tilde_g^t) * tilde_H;

        auto q = hash(sigma1_, sigma2_, tilde_sigma_, indexes, a[j](j.in(I)), i)
            .to(Zp) (i.in(Ip)) | materialize;

        auto sigma3_fixed = Π[i.in[I_plus.size()]](Y[n - Ip[i]]^(t * q[i]));
        auto sigma3_cross_terms = sequence(2uz * n + 1uz)
            | std::views::transform([&](size_t k){
                auto valid_ii = sequence(I_plus.size())
                    | filter([&](size_t ii){
                        return std::ranges::contains(J, k + I_plus[ii] - n - 1uz);
                    });
                if(not valid_ii.empty())
                {
                    return std::make_optional(Y[k]^Σ[i.in(valid_ii)](q[i] * a[k + Ip[i] - n - 1uz]));
                }
                return decltype(std::make_optional(Y[k]^Σ[i.in(valid_ii)](q[i] * a[k + Ip[i] - n - 1uz]))){ std::nullopt };
            })
            | std::views::filter([](auto&& Yk){ return Yk.has_value(); })
            | transform([](auto&& Yk){ return Yk.value(); });
        auto sigma3_ = sigma3_fixed * Π(sigma3_cross_terms);

        auto C = sigma1_^z;
        auto C0 = sigma1_^rho;
        auto c0 = hash(m, sigma1_, sigma2_, sigma3_, C, tilde_sigma_, C0).to(Zp);
        auto s0 = rho + -c0*z;

        return serialize(sigma1_, sigma2_, sigma3_, C, tilde_sigma_, c0, s0);
    }
}
