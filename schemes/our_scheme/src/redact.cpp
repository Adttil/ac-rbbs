#include <optional>

#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    OurScheme::RedactCache OurScheme::redact(
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        const UserSecretKey& usk,
        std::span<const size_t> indexes,
        const PublicKey& pk
    )
    {
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto Z = u^z;
        auto I = indexes | algebraic;
        auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });

        auto C_I = h * Π[i.in(I)](Y[n + i + 2uz]^a[i]);
        auto B = Z * C_I * (A^-w);
        auto C_J = C / (Z * C_I);
        auto q = hash(C_I, i).to(Zp) (i.in(I)) | materialize;

        auto D_fixed = Π[i.in[I.size()]](Y[n - I[i] - 1uz]^q[i]);
        auto Yks = sequence(2uz * n + 2uz)
            | std::views::transform([&](size_t k){
                auto valid_ii = sequence(I.size())
                    | filter([&](size_t ii){ return k != n && std::ranges::contains(J, k - n + I[ii]); });
                if(not valid_ii.empty())
                {
                    return std::make_optional(Y[k]^Σ[i.in(valid_ii)](q[i] * a[k - n + I[i]]));
                }
                return decltype(std::make_optional(Y[k]^Σ[i.in(valid_ii)](q[i] * a[k - n + I[i]]))){ std::nullopt };
            })
            | std::views::filter([](auto&& Yk){ return Yk.has_value(); })
            | transform([](auto&& Yk){ return Yk.value(); });

        auto D = D_fixed * Π(Yks);
        return serialize(C_I, C_J, B, D);
    }
}
