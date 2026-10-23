#include <crypto12381/crypto12381.hpp>
#include <rbbs_star.hpp>

namespace anonymous_credentials
{
    std::vector<serialized_field<Zp>> RBBSStar::generate_attributes(const PublicKey&, size_t n, RandomEngine& random)
    {
        auto a = random-select_in<Zp>(n);
        return serialize(a[i]) (i.in[n]);
    }
}
