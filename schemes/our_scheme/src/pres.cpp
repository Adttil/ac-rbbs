#include <optional>
#include <tuple>

#include <crypto12381/crypto12381.hpp>
#include <our_scheme.hpp>

namespace anonymous_credentials
{
    namespace
    {
        auto preprocess_impl(
            const auto& h,
            const auto& u,
            const auto& Y,
            const auto& a,
            const auto& A,
            const auto& C,
            const auto& w,
            const auto& z,
            std::span<const size_t> indexes
        )
        {
            const size_t n = a.size();
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
            return std::tuple{ C_I, C_J, B, D };
        }

        OurScheme::PresProof pres_impl(
            std::string_view m,
            const auto& A,
            const auto& w,
            const auto& z,
            const auto& C_I,
            const auto& C_J,
            const auto& B,
            const auto& D,
            const auto& u,
            RandomEngine& random
        )
        {
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

    OurScheme::PresProof OurScheme::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> indexes,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto [C_I, C_J, B, D] = preprocess_impl(h, u, Y, a, A, C, w, z, indexes);

        return pres_impl(m, A, w, z, C_I, C_J, B, D, u, random);
    }

    OurScheme::PresCache OurScheme::preprocess(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> indexes,
        const PublicKey& pk
    )
    {
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto [C_I, C_J, B, D] = preprocess_impl(h, u, Y, a, A, C, w, z, indexes);
        return serialize(C_I, C_J, B, D);
    }

    OurScheme::PresProof OurScheme::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>>,
        const Signature& sig,
        std::span<const size_t>,
        const PresCache& cache,
        std::string_view m,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        auto [A, C, w] = parse<G1^2|Zp>(sig);
        auto z = parse<Zp>(usk);
        auto [C_I, C_J, B, D] = parse<G1^4>(cache);
        auto [h, u, tilde_g, tilde_X] = parse<G1^2|G2^2>(pk.fixed_part);

        return pres_impl(m, A, w, z, C_I, C_J, B, D, u, random);
    }
}
