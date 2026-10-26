#include <optional>

#include <crypto12381/crypto12381.hpp>
#include <rbbs.hpp>

namespace anonymous_credentials
{
    RBBS::PresProof RBBS::pres(
        const UserSecretKey& usk,
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        std::span<const size_t> indexes,
        const PublicKey& pk,
        RandomEngine& random
    )
    {
        const auto [h, u] = parse<G1^2>(
            std::span{ pk.fixed_part }.first<serialized_size<G1^2>>());
        const auto Y = parse<G1>(pk.Y) | materialize;
        const auto a = parse<Zp>(attr) | materialize;
        const auto [A, C, w] = parse<G1^2|Zp>(sig);
        const auto z = parse<Zp>(usk);
        const size_t n = a.size();
        const auto I = indexes | algebraic;

        std::vector<size_t> index_positions(n, I.size());
        for(size_t ii = 0uz; ii < I.size(); ++ii)
        {
            index_positions[I[ii]] = ii;
        }

        const auto Z = (u^z).G1_point();
        const auto C_I = h * Π[i.in(I)](Y[n + i + 2uz]^a[i]);
        const auto B = Z * C_I * (A^-w);
        const auto C_J = C / (Z * C_I);

        const auto r = random-select_in<*Zp>;
        const auto A_ = (A^r).G1_point();
        const auto B_ = (B^r).G1_point();
        const auto C_J_ = (C_J^r).G1_point();

        const auto q = hash(C_I, C_J_, indexes, i).to(Zp) (i.in(I)) | materialize;
        const auto D_factors = sequence(2uz * n)
            | std::views::transform([&](size_t k){
                const size_t fixed_ii = k < n ? index_positions[n - k - 1uz] : I.size();
                const auto cross_ii = sequence(I.size())
                    | filter([&](size_t ii){
                        const size_t j = k + I[ii] - n;
                        return j < n && index_positions[j] == I.size();
                    });
                const auto get_cross = [&](){ return Σ[i.in(cross_ii)](q[i] * a[k + I[i] - n]); };
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
        const auto D = Π(D_factors);
        const auto D_ = (D^r).G1_point();

        const auto [alpha, beta, gamma] = random-select_in<Zp^3>;
        const auto U = (u^gamma) * (C_I^alpha) * (A_^beta);
        const auto c = hash(indexes, C_I, A_, B_, C_J_, D_, U).to(Zp);
        const auto s_r = alpha + r*c;
        const auto s_w = beta + -w*c;
        const auto s_z = gamma + r*z*c;

        return serialize(A_, B_, C_J_, D_, c, s_r, s_w, s_z);
    }
}
