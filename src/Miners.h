// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2020, DadoCoin developers
//
// You should have received a copy of the GNU Lesser General Public License
// along with this file.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstddef>
#include <initializer_list>

namespace CryptoNote {

struct MinersData {
  const char* address;
  const char* viewKey;
  const char* reserveProof;
};

const std::initializer_list<MinersData> BLESSED_MINERS = { 
  { "LuBBQf9894VFdjEbUbcDe6H6EGpnewSnSB3QLfEZmS67MA5eavrn83XcFwNNVGCjcdAtu7tQ8XEQDMjeoYpo6piwNJg63Cy", "0edb0eb985a8fd0be4a7bdd15d595570629d0f05d685a4a2eca92d531e6dbd03","RsrvPrfuDP79HsCF5vT1D9EVQNhTCqBkgGsNMU5oDtF82n28EQZPAAbbtTJfBjDw4PJECQJWF45oP9gGX3x6k4hUJAF9bmsfiNNaZuEWV7rDcF1DaKJ3VQWv1Z89YdackKaQLT6HH6LSxjX4qVS5pMw3FFVBbMW3aqDdrDYwykryjXgLDY72LBAaSUhgxNZjnWz67HbUeNSnqpbtrXQQbjdmxRMyWJkY4UdMm2ZLBq8dSUB2NjFPpWdGeRDbUf6QgK8LfDCwVWWKzNQiPWXgtpy3J46W29Was2gRMaLz3DzJLvcJCscREeakzamA5udGAxeQJEEMcRjA3hL5gSfaRUxbHMoV2627K2E5FvhjNBdVF5NxbjSRdgKoYH8sk4EKb2Mg96Vx46osEwo7nfb2KdL2Tp1pm" }
};

}
