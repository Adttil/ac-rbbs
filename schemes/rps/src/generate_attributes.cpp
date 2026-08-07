#include <crypto12381/crypto12381.hpp>
#include <rps.hpp>

namespace anonymous_credentials
{
    std::vector<serialized_field<Zp>> RPS::generate_attributes(const PublicKey&, size_t n, RandomEngine& random)
    {
        auto a = random-select_in<Zp>(n);
        return serialize(a[i]) (i.in[n]);
    }
}
