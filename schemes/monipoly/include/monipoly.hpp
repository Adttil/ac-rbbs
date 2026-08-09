#ifndef ANONYMOUS_CREDENTIALS_MONIPOLY_HPP
#define ANONYMOUS_CREDENTIALS_MONIPOLY_HPP

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <crypto12381/interface.hpp>

namespace anonymous_credentials
{
    using namespace crypto12381;

    struct MoniPoly
    {
        struct PrivateKey : serialized_field<Zp^2> {};

        struct UserSecretKey : serialized_field<Zp> {};

        struct UserPublicKey : serialized_field<G1> {};

        struct UserKeys
        {
            UserSecretKey usk;
            UserPublicKey upk;
        };

        struct PublicKey
        {
            serialized_field<G1^3, G2^2> fixed_part;
            std::vector<serialized_field<G1>> a;
            std::vector<serialized_field<G2>> tilde_a;
        };

        struct Keys
        {
            PrivateKey sk;
            PublicKey pk;
        };

        struct Signature : serialized_field<G1, Zp^3> {};

        struct PresCache : serialized_field<G1> {};

        struct PresProof : serialized_field<G1^6, Zp^5> {};

        static constexpr std::string_view name()
        {
            return "monipoly";
        }

        static Keys keygen(size_t n, RandomEngine& random);

        static UserKeys user_keygen(const PublicKey& pk, RandomEngine& random);

        static std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random);

        static Signature issue(
            const Keys& keys,
            const UserPublicKey& upk,
            std::span<const serialized_field<Zp>> attr,
            RandomEngine& random
        );

        static PresProof pres(
            const UserSecretKey& usk,
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            std::span<const size_t> I,
            std::string_view m,
            const PublicKey& pk,
            RandomEngine& random
        );

        static PresCache preprocess(
            const UserSecretKey& usk,
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            std::span<const size_t> I,
            const PublicKey& pk
        );

        static PresProof pres(
            const UserSecretKey& usk,
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            std::span<const size_t> I,
            const PresCache& cache,
            std::string_view m,
            const PublicKey& pk,
            RandomEngine& random
        );

        static bool verify(
            std::span<const serialized_field<Zp>> attr,
            std::span<const size_t> I,
            std::string_view m,
            const PresProof& proof,
            const PublicKey& pk
        );
    };

    inline constexpr MoniPoly monipoly{};
}

#endif
