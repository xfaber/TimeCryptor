using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using static mcl.MCL;

namespace TimeCryptor
{
  public class Contributor
  {
    private int k { get; set; }
    private ulong round { get; set; }
    public string Name { get; set; }
    public ECDomainParameters ecParams { get; set; }

    private BigInteger sk { get; set; }
    //public Fr t { get; set; }

    public Org.BouncyCastle.Math.EC.ECPoint PK { get; set; }
    public G2 T { get; set; } //Hex string
    public BigInteger y { get; set; }

    public bool[] b { get; set; } // contenente l'array dei bit di casaulità per la verifica delle prove
    public Proof_Item[] proof { get; set; }
    public Contributor(string contributorName, ECDomainParameters ecDomainParameters, int k, ulong round)
    {
      this.ecParams = ecDomainParameters;
      this.k = k;
      this.round = round;
      this.Name = contributorName;
    }
    public PK_T_y_ItemExtended GetPK_T_y(ulong round, G2 PKLOE, BigInteger sk)
    {
      //Init(BLS12_381);
      //ETHmode();

      var PK = ecParams.G.Multiply(sk);

      var g2Str16 = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      var T = new G2();
      var t = new Fr();
      t.SetByCSPRNG(); //sceglie ti casuale da Zp      
      g2.SetStr(g2Str16, 16);
      T.Mul(g2, t);   //Ti=g2^ti
                      //Console.WriteLine($"g2: {g2.GetStr(16).Print()}");
                      //Console.WriteLine($"t: {t.GetStr(16).Print()}");
                      //Console.WriteLine($"T: {T.GetStr(16).Print()}");

      //HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))      
      var HC = CryptoUtils.H1(round);

      var Z = new GT();
      var e = new GT();
      e.Pairing(HC, PKLOE);   // e(H1(C),PKL)
      Z.Pow(e, t);            // Zi = e(H1(C),PKL)^ti
      if (!Z.IsValid()) throw new Exception("Z not valid!");
      //Console.WriteLine($"Z: {Z.GetStr(16).Print()}");

      byte[] Zbytes = Z.Serialize();
      byte[] HashZ = CryptoUtils.GetSHA256(Zbytes); // H(Zi)
                                                    //Console.WriteLine($"Hash Z - SHA256: {BitConverter.ToString(HashZ).Replace("-","")}");

      var ZBigInt = new BigInteger(HashZ);
      var y = ZBigInt.Xor(sk);     //H(Zi) XOR ski

      //elimino dalla memoria i valori privati
      Z.Clear();
      //t.Clear(); //commentato perchè verrà cancellato quando si pubblica la tupla (PK,T,y) sulla blockchain
      sk = null;

      //Console.WriteLine($"PK: {this.PK}");
      //Console.WriteLine($"T: {T.GetStr(16)}");
      //Console.WriteLine($"y: {y.ToString(16)}");
      //ritorno i valori pubblici
      return (new PK_T_y_ItemExtended() { PK = PK, T = T, y = y, t = t });
    }

    public void PublishToBlockchain(verifyMode vm, Blockchain bc, bool simulaContributoriNonOnesto = false)
    {
      var item = new Blockchain_Item();
      item.round = this.round;
      item.pp = new PK_T_y_Item() { PK = this.PK, T = this.T, y = this.y };
      item.proof = new Proof_Item[this.k];
      for (int i = 0; i < this.k; i++)
      {
        item.proof[i] = new Proof_Item();
        item.proof[i].left = new PK_T_y_ItemExtended() { PK = this.proof[i].left.PK, T = this.proof[i].left.T, y = this.proof[i].left.y };
        item.proof[i].right = new PK_T_y_ItemExtended() { PK = this.proof[i].right.PK, T = this.proof[i].right.T, y = this.proof[i].right.y };

        // Nella verifica non interattiva viene pubblicato già il valore di t che lo smartcontract dovrà verificare
        // perchè i valori casuali dell'array b vengono determinati dalla funzione hash che fa da oracolo
        if (vm == verifyMode.NotInteractive)
        {
          //In base ai valori dell'arrtay di casualità b calcolato da Utils.GetRandomArrayForProof che implementa l'euristica di Fiat-Shamir
          switch (this.b[i])
          {
            case false:
              item.proof[i].left.t = this.proof[i].left.t;
              break;
            default:
              item.proof[i].right.t = this.proof[i].right.t;
              break;
          }
        }
      }

      if (simulaContributoriNonOnesto)
      { 
        var skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
        var sk_X = skField.ToBigInteger();
        var PK_X = ecParams.G.Multiply(sk_X);
        if (!PK_X.IsValid()) throw new Exception("PK_X not valid!");        
        item.pp.PK = PK_X;
      }

      item.contributorName = this.Name;
      Console.WriteLine($"\n=== Pubblicazione parametri della Parte {this.Name} sulla blockchain ===");
      
      Console.Write($"PK: {item.pp.PK.ToCompressedPoint()}");
      if (simulaContributoriNonOnesto) Console.WriteLine($" <--- !!! Sostituzione con chiave pubblica malevola !!!"); else Console.WriteLine("");
      Console.WriteLine($"T: {item.pp.T.ToCompressedPoint()}");
      Console.WriteLine($"y: {item.pp.y.ToString(16)}");
      bc.Put(item);
    }

    public void SetPublicParams(ulong round, G2 PKLOE)
    {
      Console.WriteLine($"\n=== Creazione parametri pubblici della Parte {this.Name} ===");
      //var array_b_string = "";

      var skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
      var sk = skField.ToBigInteger();
      this.sk = sk;
      var PK = ecParams.G.Multiply(sk);
      if (!PK.IsValid()) throw new Exception("PK not valid!");

      //CREA la lista delle tuple (〖PK〗_(j,b),T_(j,b),y_(j,b) )_(j∈[k],b∈{1,2} )
      var pp = GetPK_T_y(round, PKLOE, sk);
      //imposto i valori pubblici      
      this.PK = pp.PK;
      this.T = pp.T;
      this.y = pp.y;
      Console.WriteLine($"PK: {this.PK.ToCompressedPoint()}");
      Console.WriteLine($"T: {this.T.ToCompressedPoint()}");
      Console.WriteLine($"y: {this.y.ToString(16)}");

      this.proof = new Proof_Item[this.k];
      for (int j = 0; j < this.k; j++)
      {
        var array_sk = new BigInteger[2];
        array_sk[0] = sk;
        skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
        array_sk[0] = skField.ToBigInteger();
        while (array_sk[0].CompareTo(sk) >= 0)
        {
          var bitshift = CryptoUtils.GetSecureRandomNumberFromBC(BigInteger.One, new BigInteger(sk.BitLength.ToString(), 10)).IntValue;
          array_sk[0] = array_sk[0].ShiftRight(bitshift);
        }
        array_sk[1] = sk.Subtract(array_sk[0]);
        this.proof[j] = new Proof_Item();
        this.proof[j].left = GetPK_T_y(round, PKLOE, array_sk[0]);
        this.proof[j].right = GetPK_T_y(round, PKLOE, array_sk[1]);
      }
    }
    public BigInteger GetPrivateKey(G1 sigmaLOE)
    {
      //Init(BLS12_381);
      //ETHmode();

      var Z = new GT();
      Z.Pairing(sigmaLOE, this.T); //Zi=e(sigmaR,Ti)
      if (!Z.IsValid()) throw new Exception("Zi not valid!");
      //Console.WriteLine($"Z: {Z.GetStr(16).Print()}");

      var Zbytes = Z.Serialize();
      var hashZ = CryptoUtils.GetSHA256(Zbytes); //H(Zi)
                                                 //Console.WriteLine($"Hash Z - SHA256: {BitConverter.ToString(hashZ).Replace("-", "")}");
      var ZBigInt = new BigInteger(hashZ);
      var sk = this.y.Xor(ZBigInt);
      Console.WriteLine($"sk (tlcs): {sk.ToString(16)} (chiave segreta ricostruita)");
      Console.WriteLine($"=============================");

      return sk;
    }
    public bool CheckSK(BigInteger skToCheck)
    {
      return this.sk.Equals(skToCheck);
    }

    public bool[] GetRandomArrayForProof(int k)
    {
      var array_b_string = "";
      array_b_string += this.PK.Normalize().ToCompressedPoint().ToLower();
      for (int j = 0; j < k; j++)
      {
        array_b_string += this.proof[j].left.PK.Normalize().ToCompressedPoint().ToLower() + this.proof[j].left.T.GetStr(16) + this.proof[j].left.y;
        array_b_string += this.proof[j].right.PK.Normalize().ToCompressedPoint().ToLower() + this.proof[j].right.T.GetStr(16) + this.proof[j].right.y;
      }

      var byteArray = CryptoUtils.GetSHA256(System.Text.Encoding.UTF8.GetBytes(array_b_string));
      var bitString = "";
      for (int i = 0; i < byteArray.Length; i++)
      {
        bitString += Convert.ToString(byteArray[i], 2).PadLeft(8, '0');
        if (bitString.Length > k) break;
      }
      var retArray = new bool[k];
      for (int i = 0; i < k; i++)
      {
        retArray[i] = (bitString[i] == '1') ? true : false;
      }
      return retArray;
    }
  }
}
