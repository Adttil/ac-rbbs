#ifndef ANONYMOUS_CREDENTIALS_OUR_SCHEME_HPP
#define ANONYMOUS_CREDENTIALS_OUR_SCHEME_HPP

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <crypto12381/interface.hpp>

namespace anonymous_credentials
{
    using namespace crypto12381;

    struct OurScheme
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
            serialized_field<G1^2, G2^2> fixed_part;
            std::vector<serialized_field<G1>> Y;
            std::vector<serialized_field<G2>> tilde_Y;
        };

        struct Keys
        {
            PrivateKey sk;
            PublicKey pk;
        };

        struct Signature : serialized_field<G1^2, Zp> {};

        struct RedactCache : serialized_field<G1^4> {};

        struct PresInfo : serialized_field<G1^5, Zp^3> {};

        static constexpr std::string_view name()
        {
            return "our_scheme";
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

        static RedactCache redact(
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            const UserSecretKey& usk,
            std::span<const size_t> I,
            const PublicKey& pk
        );

        static PresInfo pres(
            std::string_view m,
            std::span<const serialized_field<Zp>> attr,
            const Signature& sig,
            std::span<const size_t> I,
            const RedactCache& redact_cache,
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

    inline constexpr OurScheme our_scheme{};
}

#endif
