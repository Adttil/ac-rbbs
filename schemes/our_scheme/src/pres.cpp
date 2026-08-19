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
            auto alpha = hash(a[i]).to(Zp) (i.in[n]) | materialize;
            auto Z = u^z;
            auto I = indexes | algebraic;
            std::vector<size_t> II(n, I.size());
            for(size_t ii = 0uz; ii < I.size(); ++ii)
            {
                II[I[ii]] = ii;
            }

            auto C_I = h * Π[i.in(I)](Y[n + i + 2uz]^alpha[i]);
            auto B = Z * C_I * (A^-w);
            auto C_J = C / (Z * C_I);
            auto q = hash(C_I, i).to(Zp) (i.in(I)) | materialize;

            auto D_factors = sequence(2uz * n)
                | std::views::transform([&](size_t k){
                    const size_t fixed_ii = k < n ? II[n - k - 1uz] : I.size();
                    const auto cross_ii = sequence(I.size())
                        | filter([&](size_t ii){
                            const size_t j = k + I[ii] - n;
                            return j < n && II[j] == I.size();
                        });
                    auto get_cross = [&](){ return Σ[i.in(cross_ii)](q[i] * alpha[k + I[i] - n]); };
                    if(fixed_ii == I.size())
                    {
                        if(cross_ii.empty())
                        {
                            return decltype(std::make_optional(Y[k]^get_cross())){ std::nullopt };
                        }
                        return std::make_optional(Y[k]^get_cross());
                    }
                    if(cross_ii.empty())
                    {
                        return std::make_optional(Y[k]^auto{ q[fixed_ii] });
                    }
                    return std::make_optional(Y[k]^(q[fixed_ii] + get_cross()).normalize());
                })
                | filter([](auto&& D_factor){ return D_factor.has_value(); })
                | transform([](auto&& D_factor){ return D_factor.value(); });

            auto D = Π(D_factors);
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

            auto c = hash(m, C_I, A_, B_, C_J_, D_, U).to(Zp);
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
        auto a = parse<Zp>(attr);
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
        auto a = parse<Zp>(attr);
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
