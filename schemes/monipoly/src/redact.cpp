#include <crypto12381/crypto12381.hpp>
#include <monipoly.hpp>

namespace anonymous_credentials
{
    auto encode(const auto& a, const auto& o, std::span<const size_t> I)
    {
        const size_t n = a.size();
        auto roots = sequence(n + 1uz) | filter([&](size_t i){ return i == n || not std::ranges::contains(I, i); });
        return std::ranges::fold_left(
            roots,
            std::views::single(make_Zp(1u)) | materialize,
            [&](auto k, size_t j)
            {
                auto root = j < n ? a[j] : o;
                const size_t degree = k.size();
                return sequence(degree + 1uz)
                    | transform([k = std::move(k), root, degree](size_t i)
                    {
                        if(i == 0uz)
                        {
                            return (k[0] * root).normalize();
                        }
                        if(i == degree)
                        {
                            return k[degree - 1uz];
                        }
                        return (k[i] * root + k[i - 1uz]).normalize();
                    })
                    | materialize;
            }
        );
    }

    MoniPoly::RedactCache MoniPoly::redact(
        std::span<const serialized_field<Zp>> attr,
        const Signature& sig,
        const UserSecretKey&,
        std::span<const size_t> I,
        const PublicKey& pk
    )
    {
        auto [v, t, s, o] = parse<G1|Zp^3>(sig);
        auto a = parse<Zp>(attr);
        auto k = encode(a, o, I);

        auto A = parse<G1>(pk.a);
        auto W0 = Π[k.size()](A[i]^k[i]);
        return serialize(W0);
    }
}
