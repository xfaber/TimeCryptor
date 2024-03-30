using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using static mcl.MCL;

namespace TimeCryptor.Classes
{
    public class PK_T_y_Item
    {
        public ECPoint PK { get; set; }
        public G2 T { get; set; }
        public BigInteger y { get; set; }
    }
}
