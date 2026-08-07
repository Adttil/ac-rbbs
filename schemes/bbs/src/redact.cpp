#include <bbs.hpp>

namespace anonymous_credentials
{
    BBS::RedactCache BBS::redact(
        std::span<const serialized_field<Zp>>,
        const Signature&,
        const UserSecretKey&,
        std::span<const size_t>,
        const PublicKey&
    )
    {
        return {};
    }
}
