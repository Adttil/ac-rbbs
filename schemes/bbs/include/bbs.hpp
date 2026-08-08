#ifndef ANONYMOUS_CREDENTIALS_BBS_HPP
#define ANONYMOUS_CREDENTIALS_BBS_HPP

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <crypto12381/interface.hpp>

namespace anonymous_credentials
{
    using namespace crypto12381;

    struct BBS
    {
        struct PrivateKey : serialized_field<Zp> {};

        struct UserSecretKey : serialized_field<Zp> {};

        struct UserPublicKey : serialized_field<G1> {};

        struct UserKeys
        {
            UserSecretKey usk;
            UserPublicKey upk;
        };

        struct PublicKey
        {
            serialized_field<G1, G2^2> fixed_part;
            std::vector<serialized_field<G1>> Y;
        };

        struct Keys
        {
            PrivateKey sk;
            PublicKey pk;
        };

        struct Signature : serialized_field<G1^2, Zp> {};

        struct PresInfo
        {
            serialized_field<G1^3, Zp^3> fixed_part;
            std::vector<serialized_field<Zp>> u;
        };

        static constexpr std::string_view name()
        {
            return "bbs";
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

        static PresInfo pres(
            std::string_view m,
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            std::span<const size_t> I,
            const UserSecretKey& usk,
            const PublicKey& pk,
            RandomEngine& random
        );

        static bool verify(
            std::string_view m,
            std::span<const serialized_field<Zp>> attr,
            std::span<const size_t> I,
            const PresInfo& pres,
            const PublicKey& pk
        );
    };

    inline constexpr BBS bbs{};
}

#endif
