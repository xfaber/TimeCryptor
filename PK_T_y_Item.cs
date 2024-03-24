using Org.BouncyCastle.Math;
using static mcl.MCL;

namespace TimeCryptor
{ 
    public class PK_T_y_Item
    {
      public Org.BouncyCastle.Math.EC.ECPoint PK { get; set; }
      public G2 T { get; set; }
      public BigInteger y { get; set; }
    }
  }
