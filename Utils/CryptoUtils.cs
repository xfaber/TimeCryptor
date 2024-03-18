using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Data;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TimeCryptor.Utils;
using static mcl.MCL;
using BigInteger = System.Numerics.BigInteger;

namespace TimeCryptor
{


  /// <summary>
  /// Parametri della curv aBaby Jub Jub in forma Montgomery
  /// </summary>
  public static class BJJDomainParameters_M
  {
    public static Org.BouncyCastle.Math.BigInteger a { get { return new Org.BouncyCastle.Math.BigInteger("168698"); } }
    //Parametri usati per le chiavi generate da stub Iovino su GitHub
    //public static Org.BouncyCastle.Math.BigInteger b { get { return Org.BouncyCastle.Math.BigInteger.One; } }

    //Parametri usati per le chiavi generate sul sito AragonZK
    public static Org.BouncyCastle.Math.BigInteger b { get { return new Org.BouncyCastle.Math.BigInteger("168700"); } }
  }

  /// <summary>
  /// Parametri della curv aBaby Jub Jub in forma Twisted Edwards
  /// </summary>
  public static class BJJDomainParameters_TE
  {
    // parametri presi da https://eips.ethereum.org/EIPS/eip-2494 e da https://docs.rs/ark-ed-on-bn254/latest/ark_ed_on_bn254/
    //Equazione della curva ax^2 + y^2 = 1 + dx^2y^2
    //La curva è definita su un campo primo finito di p elementi (con p numero primo)
    public static Org.BouncyCastle.Math.BigInteger p { get { return new Org.BouncyCastle.Math.BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"); } }

    // mumero primo a 251 bit
    public static Org.BouncyCastle.Math.BigInteger l { get { return new Org.BouncyCastle.Math.BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041"); } }

    // cofattore
    public static Org.BouncyCastle.Math.BigInteger h { get { return new Org.BouncyCastle.Math.BigInteger("8"); } }

    public static Org.BouncyCastle.Math.BigInteger n { get { return new Org.BouncyCastle.Math.BigInteger("21888242871839275222246405745257275088614511777268538073601725287587578984328"); } }

    //Generator Point G
    //Il punto G=(x,y) che genera tutti gli n punti della curva
    public static Org.BouncyCastle.Math.BigInteger Gx { get { return new Org.BouncyCastle.Math.BigInteger("995203441582195749578291179787384436505546430278305826713579947235728471134"); } }
    public static Org.BouncyCastle.Math.BigInteger Gy { get { return new Org.BouncyCastle.Math.BigInteger("5472060717959818805561601436314318772137091100104008585924551046643952123905"); } }


    //Parametri usati per le chiavi generate da stub Iovino su GitHub
    //public static Org.BouncyCastle.Math.BigInteger a { get { return new Org.BouncyCastle.Math.BigInteger("168700"); } }
    //public static Org.BouncyCastle.Math.BigInteger d { get { return new Org.BouncyCastle.Math.BigInteger("168696"); } }
    //Base Point B
    //Il punto B=(x,y) che genera il sottogruppo di punti P di Baby Jubjub soddisfacente l * P = O 
    //genera l'insieme dei punti di ordine l e origine O
    // public static Org.BouncyCastle.Math.BigInteger Bx { get { return new Org.BouncyCastle.Math.BigInteger("5299619240641551281634865583518297030282874472190772894086521144482721001553"); } }
    // public static Org.BouncyCastle.Math.BigInteger By { get { return new Org.BouncyCastle.Math.BigInteger("16950150798460657717958625567821834550301663161624707787222815936182638968203"); } }


    //Parametri usati per le chiavi generate sul sito AragonZK
    //https://github.com/arkworks-rs/algebra/blob/master/curves/ed_on_bn254/src/lib.rs
    public static Org.BouncyCastle.Math.BigInteger a { get { return new Org.BouncyCastle.Math.BigInteger("1"); } }
    public static Org.BouncyCastle.Math.BigInteger d { get { return new Org.BouncyCastle.Math.BigInteger("9706598848417545097372247223557719406784115219466060233080913168975159366771"); } }
    public static Org.BouncyCastle.Math.BigInteger Bx { get { return new Org.BouncyCastle.Math.BigInteger("19698561148652590122159747500897617769866003486955115824547446575314762165298"); } }
    public static Org.BouncyCastle.Math.BigInteger By { get { return new Org.BouncyCastle.Math.BigInteger("19298250018296453272277890825869354524455968081175474282777126169995084727839"); } }
  }

  public static class CryptoUtils
  {
    private const string _defaultIV = "\"myNE?o,CSn2_,-R";

    public static void CheckValidKeyPair(Org.BouncyCastle.Math.EC.ECPoint PK, Org.BouncyCastle.Math.BigInteger sk, ECDomainParameters ecParams)
    {
      var publicKeyPoint = ecParams.Curve.ImportPoint(PK);

      var publicKeyParameters = new ECPublicKeyParameters("EC", publicKeyPoint, ecParams);

      // Check PK
      bool isPublicKeyValid = publicKeyParameters.Q.IsValid();
      Console.WriteLine($"La chiave pubblica è {(isPublicKeyValid ? "valida" : "non valida")}.");

      // SK - PRIVATE KEY
      // Calculate PK’ – DERIVED PUBLIC KEY
      var derivedPublicKey = ecParams.G.Multiply(sk);
      Console.WriteLine($"derivedPublicKey: {derivedPublicKey.ToCompressedPoint()}");
      //derivedPublicKey.Normalize();
      //Console.WriteLine($"derivedPublicKey (normalized): {derivedPublicKey}");
      //var derivedCompressedPublicKey = CompressWeierstrassBjjPoint(derivedPublicKey.XCoord.ToBigInteger(), derivedPublicKey.YCoord.ToBigInteger());
      //Console.WriteLine($"derivedCompressedPublicKey {derivedCompressedPublicKey}");

      //var derivedPublicKeyParameters = new ECPublicKeyParameters("EC", derivedPublicKey, ecParams);
      //var pString = derivedPublicKey.ToString();
      //Console.WriteLine($"derivedPublicKey {pString}");
      // Check PK’ = PK 
      //bool arePublicKeysEqual = derivedPublicKeyParameters.Q.Equals(publicKeyParameters.Q);
      bool arePublicKeysEqual = derivedPublicKey.Equals(publicKeyParameters.Q);
      Console.WriteLine($"La chiave pubblica derivata è {(arePublicKeysEqual ? "corretta" : "NON corretta")}.");
    }

    //restituisce l'hash 256 di un array di byte passato in input
    public static byte[] GetSHA256(byte[] aBytes)
    {
      var H = new Sha256Digest();
      H.BlockUpdate(aBytes, 0, aBytes.Length);
      var hash = new byte[H.GetDigestSize()];
      H.DoFinal(hash, 0);
      return hash;
    }

    #region Curve ellittiche

    public enum ECname
    {
      FRP256v1
  , brainpoolp160r1
  , brainpoolp160t1
  , brainpoolp192r1
  , brainpoolp192t1
  , brainpoolp224r1
  , brainpoolp224t1
  , brainpoolp256r1
  , brainpoolp256t1
  , brainpoolp320r1
  , brainpoolp320t1
  , brainpoolp384r1
  , brainpoolp384t1
  , brainpoolp512r1
  , brainpoolp512t1
  /*
  , GostR3410-2001-CryptoPro-A]
  , GostR3410-2001-CryptoPro-B
  , GostR3410-2001-CryptoPro-C
  , tc26-gost-3410-2012-256paramSetA
  , tc26-gost-3410-12-512paramSetA
  , tc26-gost-3410-12-512paramSetB
  , tc26_gost_3410_12_512_paramSetC
  , P-192
  , P-224
  , P-256
  , P-384
  , P-521
  */
  , secp112r1
  , secp112r2
  , secp128r1
  , secp128r2
  , secp160k1
  , secp160r1
  , secp160r2
  , secp192k1
  , secp192r1
  , secp224k1
  , secp224r1
  , secp256k1
  , secp256r1
  , secp384r1
  , secp521r1
  , sm2p256v1
  , prime192v1
  , prime192v2
  , prime192v3
  , prime239v1
  , prime239v2
  , prime239v3
  , prime256v1
    }

    public static byte[] FromHexStr(string s)
    {
      if (s.Length % 2 == 1)
      {
        throw new ArgumentException("s.Length is odd." + s.Length);
      }
      int n = s.Length / 2;
      var buf = new byte[n];
      for (int i = 0; i < n; i++)
      {
        buf[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
      }
      return buf;
    }

    public static byte[] StringToByteArray(string hex)
    {
      return Enumerable.Range(0, hex.Length)
                       .Where(x => x % 2 == 0)
                       .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                       .ToArray();
    }

    public static ECDomainParameters GetEcDomainParametersByEcName(string curveName)
    {
      X9ECParameters ecParams = ECNamedCurveTable.GetByName(curveName);
      return new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
    }

    /// <summary>
    /// parametri curva impostati manualmente
    /// </summary>
    /// <returns></returns>
    public static ECDomainParameters ecDomainParametersDirect(string curveName)
    {
      /*
       p è il numero primo usato per generare GF(p), 
       h è il cofattore, 
       n è l'ordine del sottogruppo ciclico utilizzato (in modo che l'ordine del gruppo ciclico generato dalla curva ellittica sia h∙n), 
       Type è una descrizione della curva, ad esempio "curva di Weierstrass", 
       a e b sono i coefficienti che definiscono la curva e 
       G è un punto sulla curva che genera tutti i punti nel sottogruppo ciclico. 
       C'è un parametro opzionale {Seed, c} un numero casuale che fornisce un seme per generare i propri coefficienti a,b e un valore c per garantire che   nella curva precedente abbia una soluzione unica.
      */

      Org.BouncyCastle.Math.BigInteger p;
      Org.BouncyCastle.Math.BigInteger a;
      Org.BouncyCastle.Math.BigInteger b;
      Org.BouncyCastle.Math.BigInteger n;
      Org.BouncyCastle.Math.BigInteger h;
      Org.BouncyCastle.Math.BigInteger generatorX;
      Org.BouncyCastle.Math.BigInteger generatorY;

      // Generating EC parameters   
      switch (curveName)
      {
        case "babyjubjub":
          // Generator point TE BabyJubJub
          // parametri presi da https://eips.ethereum.org/EIPS/eip-2494 e da https://docs.rs/ark-ed-on-bn254/latest/ark_ed_on_bn254/
          //"Base Point TE"
          var generatorX_TE = BJJDomainParameters_TE.Bx;
          var generatorY_TE = BJJDomainParameters_TE.By;
          //"Generator Point TE"
          //var generatorX_TE = BJJDomainParameters_TE.Gx;
          //var generatorY_TE = BJJDomainParameters_TE.Gy;
          Console.WriteLine("\n=== Conversione punto generatore da Twisted Edwards a Weierstrass ===");
          var generatorPoint_W = ConvertFromTwistedEdwardsToWeierstrass(generatorX_TE, generatorY_TE);

          Console.WriteLine($"Coordinate Weierstrass Generatore ({generatorPoint_W.x},{generatorPoint_W.y})");

          //Calcolo dei parameri a e b 
          var a_MO = BJJDomainParameters_M.a;
          var b_MO = BJJDomainParameters_M.b;
          /*
            Reference: https://en.wikipedia.org/wiki/Montgomery_curve  
            Equation in Montgomery form: By^2 = x^3 + Ax^2 + x
            Parameters: A = 168698, B = 1
            The mapping between Montgomery M_{A, B} and Weierstrass E_{a, b} is given by the following equations:
            a = (3 - A^2) / 3, b = (2A^3 - 9A)/27, (x, y)->(u, v)=(x+A/3, y)
                        
            Se B=168700            
            a = (3 - A^2) / 3*B^2, b = (2A^3 - 9A)/27*B^3, (x, y)->(u, v)=(x/B + A/3*B, y/B)

            num/den mod p => den.ModInverse(p).Multiply(num).Mod(p)  
          */
          p = BJJDomainParameters_TE.p;
          var a_num = Org.BouncyCastle.Math.BigInteger.Three.Subtract(a_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
          var a_den = Org.BouncyCastle.Math.BigInteger.Three.Multiply(b_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
          a = a_den.ModInverse(p).Multiply(a_num).Mod(p);
          var nove = new Org.BouncyCastle.Math.BigInteger("9");
          var venti7 = new Org.BouncyCastle.Math.BigInteger("27");
          var b_num = Org.BouncyCastle.Math.BigInteger.Two.Multiply(a_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p)).Mod(p).Subtract(nove.Multiply(a_MO).Mod(p)).Mod(p);
          var b_den = venti7.Multiply(b_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p)).Mod(p);
          b = b_den.ModInverse(p).Multiply(b_num).Mod(p);
          Console.WriteLine($"Parametri Weierstrass \na: {a} \nb: {b}");

          n = BJJDomainParameters_TE.l;
          h = BJJDomainParameters_TE.h;
          generatorX = generatorPoint_W.x;
          generatorY = generatorPoint_W.y;
          break;

        case "secp256k1":
          p = new Org.BouncyCastle.Math.BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);  //anche riferito come q Base field
          a = new Org.BouncyCastle.Math.BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
          b = new Org.BouncyCastle.Math.BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
          n = new Org.BouncyCastle.Math.BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);  //anche riferito come r Scalar field
          h = Org.BouncyCastle.Math.BigInteger.One;
          generatorX = new Org.BouncyCastle.Math.BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
          generatorY = new Org.BouncyCastle.Math.BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
          /*
          p = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"));
          a = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("0000000000000000000000000000000000000000000000000000000000000000"));
          b = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("0000000000000000000000000000000000000000000000000000000000000007"));
          n = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));
          h = Org.BouncyCastle.Math.BigInteger.One;
          generatorX = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
          generatorY = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
          */
          break;

        case "brainpoolp160r1":
          p = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("E95E4A5F737059DC60DFC7AD95B3D8139515620F"));
          a = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("340E7BE2A280EB74E2BE61BADA745D97E8F7C300"));
          b = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("1E589A8595423412134FAA2DBDEC95C8D8675E58"));
          n = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("E95E4A5F737059DC60DF5991D45029409E60FC09"));
          h = Org.BouncyCastle.Math.BigInteger.One;

          generatorX = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3"));
          generatorY = new Org.BouncyCastle.Math.BigInteger(1, Hex.DecodeStrict("1667CB477A1A8EC338F94741669C976316DA6321"));
          break;

        default:
          Console.WriteLine("Curva ellittica non supportata!");
          return null;
      }

      Org.BouncyCastle.Math.EC.ECCurve curve = new FpCurve(p, a, b, n, h);
      Org.BouncyCastle.Math.EC.ECPoint generatorPoint = curve.CreatePoint(generatorX, generatorY);
      //generatorPoint = generatorPoint.Negate();

      return new ECDomainParameters(curve, generatorPoint, n, h);
    }

    /// <summary>
    /// parametri curva ellettica secp256k1 impostati tramite il nome della curva
    /// </summary>
    /// <returns></returns>
    public static ECDomainParameters ecDomainParametersBuiltIn(string curveName)
    {
      X9ECParameters ecParams = ECNamedCurveTable.GetByName(curveName);
      var domainParams = new ECDomainParameters(ecParams);
      return domainParams;
    }

    /// <summary>
    /// Once we have our elliptic curve parameters we are ready to generate a pair of asymmetric keys.
    /// Generating keys and key agreement
    /// </summary>
    /// <param name="ecParams"></param>
    /// <returns></returns>
    public static AsymmetricCipherKeyPair generateECDHKeyPair(ECDomainParameters ecParams)
    {
      ECKeyGenerationParameters ecKeyGenParams = new ECKeyGenerationParameters(ecParams, new SecureRandom()); //ExValues.cSharpFixedRandom
      ECKeyPairGenerator ecKeyPairGen = new ECKeyPairGenerator();
      ecKeyPairGen.Init(ecKeyGenParams);
      AsymmetricCipherKeyPair ecKeyPair = ecKeyPairGen.GenerateKeyPair();
      return ecKeyPair;
    }
    // Metodo per convertire il punto in formato non compresso.
    public static byte[] ToAffineUncompressed(Org.BouncyCastle.Math.BigInteger X, Org.BouncyCastle.Math.BigInteger Y)
    {
      byte[] xBytes = X.ToByteArray();
      byte[] yBytes = Y.ToByteArray();

      // Concateniamo le rappresentazioni in byte di X e Y per ottenere il formato non compresso.
      byte[] result = new byte[xBytes.Length + yBytes.Length];
      Array.Copy(xBytes, result, xBytes.Length);
      Array.Copy(yBytes, 0, result, xBytes.Length, yBytes.Length);

      return result;
    }

    #endregion


    /// <summary>
    /// Genera una stringa casuale
    /// </summary>
    /// <param name="length">Lunghezza della stringa richiesta</param>
    /// <param name="validChars">
    /// Caratteri usati per la generazione della stringa 
    /// Se non specificato vengono usati i seguenti caratteri "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?"
    /// </param>
    /// <returns></returns>
    public static string GetRandomKey(int length, string validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?")
    {
      StringBuilder key = new StringBuilder();

      Random random = new Random();
      for (int i = 0; i < length; i++)
      {
        int index = random.Next(validChars.Length);
        key.Append(validChars[index]);
      }

      return key.ToString();
    }
    // Genera un numero casuale compreso tra min e max
    public static Org.BouncyCastle.Math.BigInteger GetSecureRandomNumberFromBC(Org.BouncyCastle.Math.BigInteger min, Org.BouncyCastle.Math.BigInteger max)
    {
      var entropySource = new SecureRandom();
      SP800SecureRandomBuilder hMacSecureRandomBuilder = new SP800SecureRandomBuilder(entropySource, false);
      hMacSecureRandomBuilder.SetPersonalizationString(Encoding.UTF8.GetBytes("TIMECRYPT"));
      // hMacSecureRandomBuilder.SetSecurityStrength(256); default is 256 bits
      // hMacSecureRandomBuilder.SetEntropyBitsRequired(256); default is 256 bits

      var digestToUse = new Sha512Digest();
      HMac hmacDigest = new HMac(digestToUse);
      var nonce = Encoding.UTF8.GetBytes(GetSecureRandomNumber(1024).ToString());
      SecureRandom hmacSecureRandom = hMacSecureRandomBuilder.BuildHMac(hmacDigest, nonce, false);
      byte[] bytes = new byte[max.BitLength / 8];
      hmacSecureRandom.NextBytes(bytes);
      var number = new Org.BouncyCastle.Math.BigInteger(bytes).Mod(max.Subtract(min)).Add(min);
      return number;
    }

    /// <summary>
    /// Genera un numero casuale
    /// </summary>
    /// <param name="bitLength">Lunghezza del numero casuale in bit</param>
    /// <returns></returns>
    public static System.Numerics.BigInteger GetSecureRandomNumber(int bitLength = 256)
    {
      // Crea un oggetto RNGCryptoServiceProvider
      using (var rng = new RNGCryptoServiceProvider())
      {
        // Determina la lunghezza in byte del numero casuale desiderato
        int byteLength = bitLength / 8;

        // Crea un array di byte per contenere il numero casuale
        byte[] randomNumber = new byte[byteLength];

        // Genera il numero casuale crittograficamente sicuro
        rng.GetBytes(randomNumber);

        // Converte l'array di byte in un BigInteger
        System.Numerics.BigInteger randomBigInteger = new System.Numerics.BigInteger(randomNumber);

        // Converte il numero casuale in una rappresentazione esadecimale per la visualizzazione
        //string randomHex = BitConverter.ToString(randomNumber).Replace("-", "");
        return randomBigInteger;
      }
    }

    /// <summary>
    /// Restituisce un numero primo casuale utlilizzando una classe della libreria BouncyCasle
    /// </summary>
    /// <param name="bitLength">
    /// Lunghezza del numero primo richiesto.
    /// Se non specificata viene restituito un numero primo a 1024 bit
    /// </param>
    /// <returns></returns>
    public static Org.BouncyCastle.Math.BigInteger GetRandomPrimeNumber(int bitLength = 1024)
    {
      // Crea un nuovo digester SHA-512
      var digester = new Sha512Digest();
      // Crea un seed
      var seed = Encoding.UTF8.GetBytes(GetSecureRandomNumber(bitLength).ToString());
      // Genera un numero primo casuale di bitLength bit
      var prime = Primes.GenerateSTRandomPrime(digester, bitLength, seed);
      return prime.Prime;
    }


    private static void printBigInt(string s)
    {
      int charsPerLine = 60;
      if (s.Length < charsPerLine)
        Console.Write(s.ToString());
      else
        for (int i = 0; i < s.Length; i += charsPerLine)
        {
          //if (i != 0) { Console.WriteLine(); Console.Write("    "); }
          Console.WriteLine("    " + s.Substring(i, Math.Min(charsPerLine, s.Length - i)));
        }
      Console.WriteLine();
    }
    public static void Print(this Org.BouncyCastle.Math.BigInteger x)
    {
      printBigInt(x.ToString());
    }
    public static void Print(this BigInteger x)
    {
      printBigInt(x.ToString());
    }
    public static Org.BouncyCastle.Math.BigInteger GetRandomPrimeNumber(Org.BouncyCastle.Math.BigInteger min, Org.BouncyCastle.Math.BigInteger max)
    {
      // Crea un nuovo digester SHA-512
      var digester = new Sha512Digest();
      // Crea un seed
      var seed = Encoding.UTF8.GetBytes(GetSecureRandomNumber(max.BitLength).ToString());
      // Genera un numero primo casuale di bitLength bit
      var prime = Primes.GenerateSTRandomPrime(digester, max.BitLength, seed);

      var number = prime.Prime.Mod(max.Subtract(min)).Add(min);
      return number;
    }

    /// <summary>
    /// Restituisce la pappresentazione compressa del punto in formato esadecimale
    /// </summary>
    /// <param name="ecPoint"></param>
    /// <returns></returns>
    public static string ToCompressedPoint(this Org.BouncyCastle.Math.EC.ECPoint ecPoint)
    {
      byte[] compressedPoint = ecPoint.GetEncoded(true);
      return BitConverter.ToString(compressedPoint).Replace("-", string.Empty);
    }

    public static string ToCompressedPoint(this G1 ecPoint)
    {
      byte[] compressedPoint = ecPoint.Serialize();
      return BitConverter.ToString(compressedPoint).Replace("-", string.Empty);
    }

    public static string ToCompressedPoint(this G2 ecPoint)
    {
      byte[] compressedPoint = ecPoint.Serialize();
      return BitConverter.ToString(compressedPoint).Replace("-", string.Empty);
    }

    /// <summary>
    /// Converte Org.BouncyCastle.Math.BigInteger in System.Numerics.BigInteger
    /// </summary>
    /// <param name="n"></param>
    /// <returns></returns>
    public static BigInteger ConvertToBigInteger(this Org.BouncyCastle.Math.BigInteger n)
    {
      var systemBigInteger = BigInteger.Parse(n.ToString());
      return systemBigInteger;
    }

    /// <summary>
    /// // Converte System.Numerics.BigInteger in Org.BouncyCastle.Math.BigInteger            
    /// </summary>
    /// <param name="n"></param>
    /// <returns></returns>
    public static Org.BouncyCastle.Math.BigInteger ConvertToBigIntergerBC(this BigInteger n)
    {
      Org.BouncyCastle.Math.BigInteger bouncyCastleBigInteger = new Org.BouncyCastle.Math.BigInteger(n.ToString());
      return bouncyCastleBigInteger;
    }

    /// <summary>
    /// Restituise il generatore di un gruppo di ordine primo q
    /// </summary>
    /// <param name="q"></param>
    /// <returns></returns>
    public static BigInteger GetGenerator(BigInteger q)
    {
      //int q = 7; // Sostituisci con il tuo ordine primo
      int generator = -1; // Inizializza a un valore che indica che il generatore non è stato trovato

      for (int a = 2; a < q; a++)
      {
        bool isGenerator = true;

        for (int i = 1; i <= q - 2; i++) // Itera su tutti i possibili esponenti da 1 a q-2
        {
          BigInteger result = ModuloExponentiation(a, i, q);

          if (result == 1)
          {
            isGenerator = false;
            break;
          }
        }

        if (isGenerator)
        {
          generator = a;
          break;
        }
      }

      if (generator != -1)
      {
        Logger.Log($"Il generatore del gruppo ciclico Z/{q}Z è {generator}");
      }
      else
      {
        Logger.Log($"Nessun generatore trovato per il gruppo ciclico Z/{q}Z");
      }

      return generator;
    }

    // Funzione di esponenziazione modulare
    public static BigInteger ModuloExponentiation(BigInteger baseValue, int exponent, BigInteger modulus)
    {
      BigInteger result = 1;

      while (exponent > 0)
      {
        if (exponent % 2 == 1)
        {
          result = (result * baseValue) % modulus;
        }

        baseValue = (baseValue * baseValue) % modulus;
        exponent /= 2;
      }

      return result;
    }

    #region "Genera un numero primo"
    /// <summary>
    /// Test di primalita' di Miller-Rabin
    /// </summary>
    /// <param name="n">numero da testare</param>
    /// <param name="k">numero d iterazioni.
    /// In un contesto di crittografia per numeri a 1024 bit, 40-50 iterazioni sono considerate sufficienti per garantire una buona confidenza nella determinazione della primalità.
    /// </param>
    /// <returns></returns>
    public static bool IsPrime(BigInteger n, int k = 50)
    {
      if (n <= 1 || n == 4)
        return false;
      if (n <= 3)
        return true;

      // Trova d e r tali che n - 1 = 2^r * d con d dispari
      int r = 0;
      BigInteger d = n - 1;
      while (d % 2 == 0)
      {
        r++;
        d /= 2;
      }

      // Test di Miller-Rabin
      for (int i = 0; i < k; i++)
      {
        if (!MillerRabinTest(n, r, d))
          return false;
      }

      return true;
    }

    /// <summary>
    /// Test di primalità di Miller-Rabin
    /// </summary>
    /// <param name="n"></param>
    /// <param name="r"></param>
    /// <param name="d"></param>
    /// <returns></returns>
    static bool MillerRabinTest(BigInteger n, int r, BigInteger d)
    {
      RandomNumberGenerator rng = RandomNumberGenerator.Create();
      byte[] bytes = new byte[n.ToByteArray().Length];
      rng.GetBytes(bytes);

      BigInteger a = new BigInteger(bytes);
      a = BigInteger.Remainder(a, n - 4) + 2; // Genera un numero casuale compreso tra 2 e n-2

      BigInteger x = BigInteger.ModPow(a, d, n);

      if (x == 1 || x == n - 1)
        return true;

      for (int i = 0; i < r - 1; i++)
      {
        x = BigInteger.ModPow(x, 2, n);
        if (x == n - 1)
          return true;
      }

      return false;
    }

    public static BigInteger GeneratePrimeNumber(int numBits)
    {
      RandomNumberGenerator rng = RandomNumberGenerator.Create();
      byte[] bytes = new byte[numBits / 8];

      BigInteger primeCandidate;
      do
      {
        rng.GetBytes(bytes);
        primeCandidate = new BigInteger(bytes);
        primeCandidate = BigInteger.Remainder(primeCandidate, BigInteger.Pow(2, numBits - 1)) + BigInteger.Pow(2, numBits - 1); // Assicura che il numero abbia il numero desiderato di bit e sia dispari
      } while (!IsPrime(primeCandidate, 20)); // Il secondo argomento è il numero di iterazioni del test di Miller-Rabin

      return primeCandidate;
    }

    #endregion



    #region TLCS - Iovino

    public static byte[] StripPEM(string pem)
    {
      Regex regex = new Regex(@"(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
      string encoded = regex.Replace(pem, "$1");

      // Rimuovi eventuali caratteri di nuova riga e spazi
      encoded = encoded.Replace("\r\n", "").Replace("\n", "").Replace(" ", "");

      // Decodifica la stringa Base64
      byte[] decodedData = Convert.FromBase64String(encoded);
      return decodedData;
    }

    public static int getRoundFromDate(DateTime futureDateTime)
    {
      const int drand_genesis_time = 1692803367; //drand quicknet genesis time
      decimal futureDateTime_unix = ((DateTimeOffset)futureDateTime).ToUnixTimeSeconds();
      decimal round = ((futureDateTime_unix - drand_genesis_time) / 3); //Valore intero minimo maggiore o uguale a round (arrotondamento divisione per eccesso es. 1.3 => 2)
      var ret = Math.Ceiling(round);
      return (int)ret;
    }

    public static KeypairsGenerationData TLCS_GenerateKey(DateTime futureDateTime, int pubKeyTimeOffsetSeconds)
    {
      /*
        roundtime '2023-12-18T13:01'
        time 1702900860000
        unixTimestamp 1702900860
        round 3365831
        pubkeytime '2023-12-18T13:08'
      */

      var scheme = 2;                               // 2 - curva secp256k1 1 - babyjubjub 
      var pubKeyTime = DateTime.Now.AddSeconds(pubKeyTimeOffsetSeconds); //.AddMinutes(1);  // (2023, 12, 18, 13, 01, 00);

      if (futureDateTime <= pubKeyTime) throw new Exception("Scegliere futureDateTime maggiore.");

      var pubKeyTime_unix = ((DateTimeOffset)pubKeyTime).ToUnixTimeSeconds();   //tempo: quando verrà pubblicata la chiave pubblica

      var round = getRoundFromDate(futureDateTime);                             //numero di round: quando verrà pubblivata la chiave privata

      //var loeRound = TLCS_GetLatestLoeround() + 35;
      //if (round < loeRound) throw new Exception("Scegli una futureDateTime successiva.");

      var url = $"https://demo.timelock.zone/keypair/{round}/{scheme}/{pubKeyTime_unix}";

      HttpResponseMessage response;
      //RICHIEDE LA GENERAZIONE DELLE CHIAVI
      //Request (Es.  https://demo.timelock.zone/keypair/3139851/2/1702222860 )
      HttpClient client = new HttpClient();
      client.BaseAddress = new Uri(url);
      using (var request = new HttpRequestMessage())
      {
        request.Method = HttpMethod.Get;
        request.RequestUri = new Uri(url);
        response = client.SendAsync(request).GetAwaiter().GetResult();
      }

      if (!response.IsSuccessStatusCode) throw new Exception($"Errore richiesta generazione chiavi:\nStatus Code: {response.StatusCode} \nReasonPhrase: {response.ReasonPhrase} \nRequestMessage: {response.RequestMessage}");

      var retData = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
      //il json restituito sembra non essere formattato correttamente elimino la parte iniziale per deserializzare correttmanete.
      /*
       Round: {
        "check_tx": {
          "code": 0,
          "data": null,
          "log": "",
          "info": "",
          "gas_wanted": "1",
          "gas_used": "0",
          "events": [],
          "codespace": "",
          "sender": "",
          "priority": "0",
          "mempool_error": ""
        },
        "deliver_tx": {
          "code": 1,
          "data": null,
          "log": "invalid request: The keypair request is invalid",
          "info": "",
          "gas_wanted": "0",
          "gas_used": "0",
          "events": [],
          "codespace": ""
        },
        "hash": "562A568E6B96EBEC37DB5B3BD652FDEB84F6457721D84B12807FFB219357AEFE",
        "height": "674892"
      }
      */
      var retJsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject<KeypairsGenerationData>(retData.Substring(7));

      return retJsonObj;
    }

    public static int TLCS_GetLatestLoeRound()
    {
      //RECUPERA L'ultimo ROUND DI LOE
      var url = $"https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest";

      var client = new HttpClient();
      client.BaseAddress = new Uri(url);
      HttpResponseMessage response;
      using (var request = new HttpRequestMessage())
      {
        request.Method = HttpMethod.Get;
        request.RequestUri = new Uri(url);
        response = client.SendAsync(request).GetAwaiter().GetResult();
      }
      if (!response.IsSuccessStatusCode) throw new Exception($"Errore richiesta latest LOE round: {response.RequestMessage}");

      var retData = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
      var retJsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject<LoeRound>(retData);

      return retJsonObj.round;
    }


    public static TlcsKeyPairs TLCS_GetKeyPair(DateTime futureDateTime, int scheme = 2)
    {
      //RECUPERA LA CHIAVE DI ROUND
      var round = getRoundFromDate(futureDateTime);

      //Request (es. https://demo.timelock.zone/tlcs/timelock/v1beta1/keypairs/round_and_scheme/3139851/2 )
      var url = $"https://demo.timelock.zone/tlcs/timelock/v1beta1/keypairs/round_and_scheme/{round}/{scheme}";

      var client = new HttpClient();
      client.BaseAddress = new Uri(url);
      HttpResponseMessage response;
      using (var request = new HttpRequestMessage())
      {
        request.Method = HttpMethod.Get;
        request.RequestUri = new Uri(url);
        response = client.SendAsync(request).GetAwaiter().GetResult();
      }
      if (!response.IsSuccessStatusCode) throw new Exception($"Errore richiesta recupero chiavi: \nStatus Code: {response.StatusCode} \nReasonPhrase: {response.ReasonPhrase} \nRequestMessage: {response.RequestMessage}");

      var retData = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
      var retJsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject<TlcsKeyPairs>(retData);

      return retJsonObj;
    }

    public static string TLCS_Encrypt(string message, AsymmetricKeyParameter privateKeySender, string tlcsPublicKey, DateTime futureTime, int scheme = 2)
    {
      Org.BouncyCastle.Crypto.AsymmetricKeyParameter pk = null;

      if (System.String.IsNullOrEmpty(tlcsPublicKey))
      {
        // RECUPERA LA CHIAVE DI ROUND (PUBBLICA) DAL SERVIZIO
        var retJsonObj = TLCS_GetKeyPair(futureTime);
        //var pk = CryptoUtils.StripPEM(retJsonObj.keypairs[0].public_key_pem);
        var sr = new StringReader(retJsonObj.keypairs[0].public_key_pem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
        pk = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)pemReader.ReadObject();
      }
      else
      {
        // RECUPERA LA CHIAVE DI ROUND (PUBBLICA) PASSATA COME PARAMETRO
        byte[] compressedKeyBytes = Hex.Decode(tlcsPublicKey.Substring(2));
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, SecObjectIdentifiers.SecP256k1);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, compressedKeyBytes);
        pk = PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
      }

      // CIFRA
      //var cipherText = ECIES.VirgilEncrypt(message, pk);
      var cipherText = ECIES.Encrypt(message, privateKeySender, pk);
      var cipherTextString = Convert.ToBase64String(cipherText);

      Logger.Log($"Testo originale: {message}");
      Logger.Log($"Testo cifrato: {cipherTextString}");
      return cipherTextString;
    }
    public static string TLCS_Decrypt(string cipherText, AsymmetricKeyParameter publicKeySender, string tlcsPrivateKeyHex, DateTime futureDateTime, int scheme = 2)
    {
      Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = null;

      if (System.String.IsNullOrEmpty(tlcsPrivateKeyHex))
      {
        // RECUPERA LA CHIAVE DI ROUND (PRIVATA) DAL SERVIZIO 
        var retJsonObj = TLCS_GetKeyPair(futureDateTime);
        if (System.String.IsNullOrEmpty(retJsonObj.keypairs[0].private_key_pem)) throw new Exception("Chiave privata non pubblicata. Riprovare piu tardi.");
        var sr = new StringReader(retJsonObj.keypairs[0].private_key_pem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
        keyPair = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)pemReader.ReadObject();
      }
      else
      {
        // RECUPERA LA CHIAVE DI ROUND (PRIVATA) PASSATA COME PARAMETRO
        var ecPrivateKeyParamsD = new Org.BouncyCastle.Math.BigInteger(tlcsPrivateKeyHex.Substring(2), 16);
        var ecParameters = CryptoUtils.ecDomainParametersBuiltIn("secp256k1");
        var privateKeyParameters = new ECPrivateKeyParameters(ecPrivateKeyParamsD, ecParameters);

        // Deriva la chiave pubblica
        var derivedPublicKeyParameters = new ECPublicKeyParameters("EC", ecParameters.G.Multiply(ecPrivateKeyParamsD), ecParameters);
        keyPair = new AsymmetricCipherKeyPair(derivedPublicKeyParameters, privateKeyParameters);
      }

      // DECIFRA
      var cipherTextByte = Convert.FromBase64String(cipherText);
      //var plainText = ECIES.VirgilDecrypt(cipherTextByte, sk);
      var plainText = ECIES.Decrypt(cipherTextByte, publicKeySender, keyPair.Private);

      Logger.Log($"Testo cifrato: {cipherText}");
      Logger.Log($"Testo decifrato: {plainText}");
      return plainText;
    }
    #endregion

    #region Cifratura con classi .Net Core (System.Security.Cryptography)

    // Funzione per cifrare una stringa con AES CBC
    public static string AES_Encrypt(string key, string plainText, string IV = _defaultIV)
    {
      // Chiave segreta per la cifratura e la decifratura
      byte[] keyBytes = Encoding.UTF8.GetBytes(key);
      // Converti il testo in un array di byte
      byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

      byte[] encryptedBytes;

      var encryptedText = "";
      using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
      {
        aesAlg.Key = keyBytes;
        //aesAlg.GenerateIV(); // Genera un IV (Initialization Vector) casuale
        aesAlg.IV = Encoding.UTF8.GetBytes(IV);
        // Cifra il testo
        encryptedBytes = Encrypt(aesAlg, plainBytes);
        encryptedText = Convert.ToBase64String(encryptedBytes);
        Logger.Log("===== AES Encrypt (System.Security.Cryptography) =====");
        Logger.Log($"Testo originale: {plainText}");
        Logger.Log($"Testo cifrato: {encryptedText}");
      }
      return encryptedText;
    }

    // Funzione per cifrare una string con AES CBC
    public static string AES_Decrypt(string key, string cipherText, string IV = _defaultIV)
    {
      // Chiave segreta per la cifratura e la decifratura
      byte[] keyBytes = Encoding.UTF8.GetBytes(key);
      // Converti il testo in un array di byte
      byte[] encryptedBytes = Convert.FromBase64String(cipherText);

      string decryptedText;

      using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
      {
        aesAlg.Key = keyBytes;
        //aesAlg.GenerateIV(); // Genera un IV (Initialization Vector) casuale
        aesAlg.IV = Encoding.UTF8.GetBytes(IV);

        // Decifra il testo cifrato
        byte[] decryptedBytes = Decrypt(aesAlg, encryptedBytes);

        // Converte il testo decifrato in una stringa
        decryptedText = Encoding.UTF8.GetString(decryptedBytes);

        Logger.Log("===== AES Decrypt (System.Security.Cryptography) =====");
        Logger.Log($"Testo cifrato: {cipherText}");
        Logger.Log($"Testo decifrato: {decryptedText}");
      }
      return decryptedText;
    }

    // Funzione per cifrare un array di byte
    public static byte[] Encrypt(SymmetricAlgorithm algorithm, byte[] inputBytes)
    {
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
        {
          cs.Write(inputBytes, 0, inputBytes.Length);
          cs.Close();
        }
        return ms.ToArray();
      }
    }

    // Funzione per decifrare un array di byte
    public static byte[] Decrypt(SymmetricAlgorithm algorithm, byte[] encryptedBytes)
    {
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
        {
          cs.Write(encryptedBytes, 0, encryptedBytes.Length);
          cs.Close();
        }
        return ms.ToArray();
      }
    }
    #endregion

    #region Cifratura con classi BouncyCastle
    /// <summary>
    /// Cifra un testo di 8 byte usando RC5
    /// La combinazione inizialmente suggerita dall'autore (Rivest) è di 12 round con una chiave da 128 bit e con blocchi da 64 bit.
    /// </summary>
    /// <param name="keyString">La chiave da usare per la cifratura</param>
    /// <param name="plainText">Il messaggio da cifrare</param>
    /// <returns></returns>
    public static string Rc5_Encrypt(string keyString, string plainText)
    {
      // Chiave segreta per la cifratura e la decifratura
      byte[] key = Encoding.UTF8.GetBytes(keyString);

      // Converti il testo in un array di byte
      byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

      // Crea un cifrario RC5            
      IBlockCipher cipher = new RC532Engine();

      // Imposta la chiave segreta
      RC5Parameters cipherParams = new RC5Parameters(key, 12);
      //KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("RC5", key);
      cipher.Init(true, cipherParams);

      // Cifra il testo
      byte[] encryptedBytes = new byte[cipher.GetBlockSize()];
      cipher.ProcessBlock(plainBytes, 0, encryptedBytes, 0);

      var encryptedText = Convert.ToBase64String(encryptedBytes);
      //Logger.Log("===== RC5 Encrypt (BouncyCastle) =====");
      //Logger.Log($"Testo originale: {plainText}");
      //Logger.Log($"Testo cifrato: {encryptedText}");

      return Convert.ToBase64String(encryptedBytes);
    }

    public static string Rc5_Decrypt(string keyString, string cipherText)
    {
      // Chiave segreta per la cifratura e la decifratura
      byte[] key = Encoding.UTF8.GetBytes(keyString);

      // Converti il testo in un array di byte
      byte[] encryptedBytes = Convert.FromBase64String(cipherText);

      // Crea un cifrario RC5            
      IBlockCipher cipher = new RC532Engine();

      // Imposta la chiave segreta
      var rounds = 12;
      RC5Parameters cipherParams = new RC5Parameters(key, rounds);

      // Decifra il testo cifrato
      cipher.Init(false, cipherParams);
      byte[] decryptedBytes = new byte[cipher.GetBlockSize()];
      cipher.ProcessBlock(encryptedBytes, 0, decryptedBytes, 0);

      // Converte il testo decifrato in una stringa
      string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

      //Logger.Log("===== RC5 Decrypt (BouncyCastle) =====");
      //Logger.Log($"Testo cifrato: {cipherText}");
      //Logger.Log($"Testo decifrato: {decryptedText}");

      return decryptedText;
    }
    #endregion

    public static string InsertChars(this string input, char character, int position, int repeatCount)
    {
      if (position < 0 || position > input.Length)
      {
        throw new ArgumentOutOfRangeException(nameof(position), "Invalid position");
      }

      if (repeatCount < 0)
      {
        throw new ArgumentOutOfRangeException(nameof(repeatCount), "Repeat count must be non-negative");
      }

      string repeatedCharacters = new string(character, repeatCount);
      return input.Insert(position, repeatedCharacters);
    }


    public static (Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y) DecompressWeierStrassBjjKey(string keyHex)
    {
      Console.WriteLine($"=== DecompressWeierStrassBjjKey ( keyHex: {keyHex} ) ===");
      if (keyHex.Substring(4).Length < 64) keyHex = keyHex.InsertChars('0', 4, 64 - keyHex.Substring(4).Length);

      var x_W = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4, 64), 16);
      Org.BouncyCastle.Math.BigInteger y_W;
      var prefix = keyHex.Substring(2, 2);
      if (prefix == "04") // il punto è non compresso
        y_W = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4 + 64, 64), 16);
      else
      {
        var segno_y = (prefix == "02") ? 1 : -1;
        //la chiave compressa contiene la sola coordinata x del punto ed il segno della y (nelle prime due cifre)
        //domain parameters JubJub (twistded edwards form)
        var p = BJJDomainParameters_TE.p;
        //var a_W = new Org.BouncyCastle.Math.BigInteger("7296080957279758407415468581752425029516121466805344781232734728849116493472");
        //var b_W = new Org.BouncyCastle.Math.BigInteger("16213513238399463127589930181672055621146936592900766180517188641980520820846");

        var a_W = new Org.BouncyCastle.Math.BigInteger("3915561033734670630843635270522714716872400990323396055797168613637673095919");
        var b_W = new Org.BouncyCastle.Math.BigInteger("4217185138631398382466346491768379401896178114478749112717062407767665636606");

        // babyjubjub Weierstrass y^2 = x^3 + ax + b ==>  ricavo y in funzione di x ==> y = sqrt (x^3 + ax + b)
        y_W = x_W.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p).Add((a_W.Multiply(x_W)).Mod(p)).Add(b_W).Mod(p);
        Console.WriteLine($"Weierstrass x^3 + ax + b: {y_W}");

        Org.BouncyCastle.Math.BigInteger sqrt;
        sqrt = ressol(y_W, p);
        Console.WriteLine($"sqrt \n sqrt: {sqrt}");

        var sqrt1 = ShankTonelliSqrtModP(y_W.ConvertToBigInteger(), p.ConvertToBigInteger());
        Console.WriteLine($"sqrt1 \n root1: {sqrt1.Root1()} \n root2: {sqrt1.Root2()}");
        CheckPointOnBjjCurveWeierstrass(x_W, sqrt1.Root1().ConvertToBigIntergerBC());
        CheckPointOnBjjCurveWeierstrass(x_W, sqrt1.Root2().ConvertToBigIntergerBC());

        if (sqrt.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p).CompareTo(y_W) != 0) { y_W = p.Subtract(sqrt); }
        else { y_W = sqrt; }
      }
      Console.WriteLine("\n===a Chiave PK - Weierstrass ===");
      Console.WriteLine($"publicKeyHex: {keyHex}");
      Console.WriteLine($"Punto decompresso ({x_W}, {y_W}).");

      CheckPointOnBjjCurveWeierstrass(x_W, y_W);

      return (x_W, y_W);
    }

    public static (Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y) DecompressMontgomeryBjjKey(string keyHex)
    {
      if (keyHex.Substring(4).Length < 64) keyHex = keyHex.InsertChars('0', 4, 64 - keyHex.Substring(4).Length);

      var x_MO = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4, 64), 16);
      Org.BouncyCastle.Math.BigInteger y_MO;
      var prefix = keyHex.Substring(2, 2);
      if (prefix == "04") // il punto è decompresso
        y_MO = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4 + 64, 64), 16);
      else
      {
        var segno_y = (prefix == "02") ? 1 : -1;
        //la chiave compressa contiene la sola coordinata x del punto ed il segno della y (nelle prime due cifre)
        //domain parameters JubJub (twistded edwards form)
        var p = BJJDomainParameters_TE.p;
        var a_MO = BJJDomainParameters_M.a;
        var b_MO = BJJDomainParameters_M.b;
        //Montgomery By^2 = x^3 + Ax^2 + x (dato che B=1) ==>  y^2 = x^3 + Ax^2 + x
        // babyjubjub Montgomery y^2 = x^3 + Ax^2 + x ==>  ricavo y in funzione di x ==> y = sqrt( x^3 + Ax^2 + x )
        y_MO = x_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p)
                   .Add((a_MO.Multiply(x_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p))).Mod(p))
                   .Add(x_MO).Mod(p);
        y_MO = b_MO.ModInverse(p).Multiply(y_MO).Mod(p);
        Console.WriteLine($"Montgomery x^3 + Ax^2 + x: {y_MO}");

        Org.BouncyCastle.Math.BigInteger sqrt;
        sqrt = ressol(y_MO, p); //calcollo della radice quadrata modulo p
        Console.WriteLine($"sqrt \n sqrt: {sqrt}");
        var sqrt1 = ShankTonelliSqrtModP(y_MO.ConvertToBigInteger(), p.ConvertToBigInteger());
        Console.WriteLine($"sqrt1 \n root1: {sqrt1.Root1()} \n root2:{sqrt1.Root2()}");
        CheckPointOnBjjCurveMontgomery(x_MO, sqrt1.Root1().ConvertToBigIntergerBC());
        CheckPointOnBjjCurveMontgomery(x_MO, sqrt1.Root2().ConvertToBigIntergerBC());

        if (sqrt.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p).CompareTo(y_MO) != 0) { y_MO = p.Subtract(sqrt); }
        else { y_MO = sqrt; }
      }
      Console.WriteLine("\n=== Chiave PK - Montgomery ===");
      Console.WriteLine($"publicKeyHex: {keyHex}");
      Console.WriteLine($"Punto decompresso ({x_MO}, {y_MO}).");

      CheckPointOnBjjCurveMontgomery(x_MO, y_MO);

      return (x_MO, y_MO);
    }


    /// <summary>
    /// decomprime la chiave resituendo la coppia di coordinate del punto della curva
    /// </summary>
    /// <param name="keyHex"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    public static (Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y) DecompressTwistedEdwardsBjjKey(string keyHex)
    {
      Console.WriteLine("=== DecompressTwistedEdwardsBjjKey ===");
      if (keyHex.Substring(4).Length < 64) keyHex = keyHex.InsertChars('0', 4, 64 - keyHex.Substring(4).Length);

      var x_TE = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4, 64), 16);

      Org.BouncyCastle.Math.BigInteger y_TE;
      var prefix = keyHex.Substring(2, 2);
      if (prefix == "04") // il punto è decompresso
      {
        y_TE = new Org.BouncyCastle.Math.BigInteger(keyHex.Substring(4 + 64, 64), 16);
        var segno_y = y_TE.TestBit(0);
      }
      else
      {
        var segno_y = (prefix == "02") ? 1 : -1;
        //la chiave compressa contiene la sola coordinata x del punto ed il segno della y (nelle prime due cifre)
        var p = BJJDomainParameters_TE.p;
        var a_TE = BJJDomainParameters_TE.a;
        var d_TE = BJJDomainParameters_TE.d;

        // babyjubjub Twisted Edwards ax^2 + y^2 = 1 + dx^2y^2 ==>  ricavo y in funzione di x ==> y = sqrt( (1 - a*x^2) / (1 - d*x^2) )
        var y_TE_num = Org.BouncyCastle.Math.BigInteger.One.Subtract(a_TE.Multiply(x_TE.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p)).Mod(p);
        var y_TE_den = Org.BouncyCastle.Math.BigInteger.One.Subtract(d_TE.Multiply(x_TE.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p)).Mod(p);
        y_TE = y_TE_den.ModInverse(p).Multiply(y_TE_num).Mod(p); // y^2
        Console.WriteLine($"Twisted Edwards (1 - a*x^2) / (1 - d*x^2)): {y_TE}");

        Org.BouncyCastle.Math.BigInteger sqrt;
        sqrt = ressol(y_TE, p);
        Console.WriteLine($"sqrt \n sqrt: {sqrt}");

        var sqrt1 = ShankTonelliSqrtModP(y_TE.ConvertToBigInteger(), p.ConvertToBigInteger());
        Console.WriteLine($"sqrt1 \n root1: {sqrt1.Root1()} \n root2: {sqrt1.Root2()}");
        CheckPointOnBjjCurveTwistedEdwards(x_TE, sqrt1.Root1().ConvertToBigIntergerBC());
        CheckPointOnBjjCurveTwistedEdwards(x_TE, sqrt1.Root2().ConvertToBigIntergerBC());

        if (segno_y < 0) { y_TE = p.Subtract(sqrt); } else { y_TE = sqrt; }
      }
      Console.WriteLine("\n=== Chiave PK - Twisted Edwards ===");
      Console.WriteLine($"publicKeyHex: {keyHex}");
      Console.WriteLine($"Punto ({x_TE}, {y_TE}).");

      CheckPointOnBjjCurveTwistedEdwards(x_TE, y_TE);

      return (x_TE, y_TE);
    }

    /// <summary>
    /// //Check the point is on curve BJJ TW form a*x^2 + y^2 = 1 + d*x^2*y^2
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <returns></returns>
    public static bool CheckPointOnBjjCurveTwistedEdwards(Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y)
    {
      var ret = false;

      //domain parameters JubJub (twistded edwards form)
      var p = BJJDomainParameters_TE.p;
      var a_TE = BJJDomainParameters_TE.a;
      var d_TE = BJJDomainParameters_TE.d;

      var eq_left = a_TE.Multiply(x.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p).Add(y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
      var eq_right = Org.BouncyCastle.Math.BigInteger.One
                     .Add(
                            d_TE.Multiply(x.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p)
                            .Multiply(y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p)
                         ).Mod(p);
      ret = (eq_left.CompareTo(eq_right) == 0);
      Console.WriteLine($"Coordinate Twisted Edwards ({x},{y}) {(ret ? "è" : "NON è")} sulla curva.");

      return ret;
    }


    public static bool CheckPointOnBjjCurveMontgomery(Org.BouncyCastle.Math.BigInteger X, Org.BouncyCastle.Math.BigInteger Y)
    {
      var ret = false;
      //Montgomery By^2 = x^3 + Ax^2 + x (se B=1) ==>  y^2 = x^3 + Ax^2 + x
      var p = BJJDomainParameters_TE.p;
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;
      var eq_left = b_MO.Multiply(Y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
      var eq_right = X.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p).Add(a_MO.Multiply(X.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p))).Mod(p).Add(X).Mod(p);
      ret = (eq_left.CompareTo(eq_right) == 0);
      Console.WriteLine($"Coordinate Montgomery ({X},{Y}) {(ret ? "è" : "NON è")} sulla curva.");

      return ret;
    }
    public static (Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y) ConvertFromMontgomeryToWeierstrass(Org.BouncyCastle.Math.BigInteger x_MO, Org.BouncyCastle.Math.BigInteger y_MO)
    {
      Console.WriteLine($"Coordinate Montgomery ({x_MO},{y_MO})");
      //domain parameters JubJub
      var p = BJJDomainParameters_TE.p;

      //Montgomery By^2 = x^3 + Ax^2 + x (se B=1) ==>  y^2 = x^3 + Ax^2 + x
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;
      // Conversion Montgomery to Weierstrass is (X, Y)->(x_W, y_W) = (X + A/3, Y)
      // ATTENZIONE Se B è diverso da 1 ==>  (X, Y)->(x_W, y_W) = (X/B + A/3*B, Y/B)
      var x_W = b_MO.ModInverse(p).Multiply(x_MO).Mod(p).Add((Org.BouncyCastle.Math.BigInteger.Three.Multiply(b_MO).Mod(p)).ModInverse(p).Multiply(a_MO).Mod(p)).Mod(p);
      var y_W = b_MO.ModInverse(p).Multiply(y_MO).Mod(p);

      //Console.WriteLine($"Coordinate Weierstrass ({x_W},{y_W})");

      CheckPointOnBjjCurveWeierstrass(x_W, y_W);

      return (x_W, y_W);
    }

    public static bool CheckPointOnBjjCurveWeierstrass(Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y)
    {
      var ret = false;

      /*
        Reference: https://en.wikipedia.org/wiki/Montgomery_curve  
        Equation in Montgomery form: By^2 = x^3 + Ax^2 + x
        Parameters: A = 168698, B = 1
        The mapping between Montgomery M_{A, B} and Weierstrass E_{a, b} is given by the following equations:
        a = (3 - A^2) / 3, b = (2A^3 - 9A)/27, (x, y)->(u, v)=(x+A/3, y)
        Se B è diverso da 1 ==>  a = (3 - A^2) / 3*B^2, b = (2A^3 - 9A)/27*B^3, (x, y)->(u, v)=(x/B + A/3*B, y/B)
        
        num/den mod p => den.ModInverse(p).Multiply(num).Mod(p)  
      */
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;

      //domain parameters JubJub in Weierstrass form
      var p = BJJDomainParameters_TE.p;
      var a_num = Org.BouncyCastle.Math.BigInteger.Three.Subtract(a_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
      var a_den = Org.BouncyCastle.Math.BigInteger.Three.Multiply(b_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p)).Mod(p);
      var a = a_den.ModInverse(p).Multiply(a_num).Mod(p);
      var nove = new Org.BouncyCastle.Math.BigInteger("9");
      var venti7 = new Org.BouncyCastle.Math.BigInteger("27");
      var b_num = Org.BouncyCastle.Math.BigInteger.Two.Multiply(a_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p)).Mod(p).Subtract(nove.Multiply(a_MO).Mod(p)).Mod(p);
      var b_den = venti7.Multiply(b_MO.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p)).Mod(p);
      var b = b_den.ModInverse(p).Multiply(b_num).Mod(p);
      Console.WriteLine($"Parametri Weierstrass \na: {a} \nb: {b}");

      // y^2 = x^3+ax+b
      var sx = y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p);
      var dx = x.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p).Add(a.Multiply(x).Mod(p)).Mod(p).Add(b).Mod(p);
      var satisfy = (sx.CompareTo(dx) == 0);
      Console.WriteLine($"Coordinate Weierstrass ({x},{y}) {(satisfy ? "è" : "NON è")} sulla curva.");

      return ret;
    }

    public static (Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y) ConvertFromTwistedEdwardsToWeierstrass(Org.BouncyCastle.Math.BigInteger x_TE, Org.BouncyCastle.Math.BigInteger y_TE)
    {
      //Console.WriteLine($"Coordinate Twisted Edwards ({x_TE},{y_TE})");
      //domain parameters JubJub
      var p = BJJDomainParameters_TE.p;

      // Conversion from Twisted Edwards to Montgomery is (x,y)->(X,Y)=((1+y)/(1-y),(1+y)/((1-y)x))
      var UnoPiuY = Org.BouncyCastle.Math.BigInteger.One.Add(y_TE).Mod(p);
      var UnoMenoY = Org.BouncyCastle.Math.BigInteger.One.Subtract(y_TE).Mod(p);
      var UnoMenoYX = UnoMenoY.Multiply(x_TE).Mod(p);
      var X = UnoMenoY.ModInverse(p).Multiply(UnoPiuY).Mod(p);
      var Y = UnoMenoYX.ModInverse(p).Multiply(UnoPiuY).Mod(p);

      //Montgomery By^2 = x^3 + Ax^2 + x (dato che B=1) ==>  y^2 = x^3 + Ax^2 + x
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;

      //conversion from TE to MO A=2*(a+d)/(a-d) B=4/(a-d)
      var a_meno_d = BJJDomainParameters_TE.a.Subtract(BJJDomainParameters_TE.d).Mod(p);
      var a_piu_d = BJJDomainParameters_TE.a.Add(BJJDomainParameters_TE.d).Mod(p);
      var a2_MO = a_meno_d.ModInverse(p).Multiply(Org.BouncyCastle.Math.BigInteger.Two.Multiply(a_piu_d).Mod(p)).Mod(p);
      var b2_MO = a_meno_d.ModInverse(p).Multiply(Org.BouncyCastle.Math.BigInteger.Four).Mod(p);

      CheckPointOnBjjCurveMontgomery(X, Y);

      //https://en.wikipedia.org/wiki/Montgomery_curve
      // Se B=1 ==> Conversion Montgomery to Weierstrass is (X, Y)->(x_W, y_W) = (X + A/3, Y)
      // Se B non è = 1 ==> Conversion Montgomery to Weierstrass is (X, Y)->(x_W, y_W) = (X/B + A/3B, Y/B)

      // num / den mod p => den.ModInverse(p).Multiply(num).Mod(p)
      var XsuB = b_MO.ModInverse(p).Multiply(X).Mod(p);
      var Asu3B = (Org.BouncyCastle.Math.BigInteger.Three.Multiply(b_MO).Mod(p)).ModInverse(p).Multiply(a_MO).Mod(p);
      var x_W = XsuB.Add(Asu3B).Mod(p);    //X.Add(Org.BouncyCastle.Math.BigInteger.Three.ModInverse(p).Multiply(a_MO).Mod(p)).Mod(p);      
      var y_W = b_MO.ModInverse(p).Multiply(Y).Mod(p);

      //Console.WriteLine($"Coordinate Weierstrass ({x_W},{y_W})");

      CheckPointOnBjjCurveWeierstrass(x_W, y_W);

      return (x_W, y_W);
    }
    public static string CompressWeierstrassBjjPoint(Org.BouncyCastle.Math.BigInteger x, Org.BouncyCastle.Math.BigInteger y)
    {
      //02: positivo - 03: negativo
      var segno_y_code = (y.TestBit(0) == false) ? "02" : "03";
      var x_hex = x.ConvertToBigInteger().ToString("X");
      x_hex = "00000" + x_hex;
      x_hex = x_hex.Substring(x_hex.Length - 64, 64);
      var publicKeyHex = $"0x{segno_y_code}{x_hex}";

      Console.WriteLine("\n=== Chiave PK - Weierstrass ===");
      Console.WriteLine($"publicKeyHex: {publicKeyHex}");
      Console.WriteLine($"Punto ({x}, {y}).");

      return publicKeyHex;
    }

    public static ST_Solution ShankTonelliSqrtModP(BigInteger n, BigInteger p)
    {
      if (BigInteger.ModPow(n, (p - 1) / 2, p) != 1)
      {
        return new ST_Solution(0, 0, false);
      }

      BigInteger q = p - 1;
      BigInteger ss = 0;
      while ((q & 1) == 0)
      {
        ss = ss + 1;
        q = q >> 1;
      }

      if (ss == 1)
      {
        BigInteger r1 = BigInteger.ModPow(n, (p + 1) / 4, p);
        return new ST_Solution(r1, p - r1, true);
      }

      BigInteger z = 2;
      while (BigInteger.ModPow(z, (p - 1) / 2, p) != p - 1)
      {
        z = z + 1;
      }
      BigInteger c = BigInteger.ModPow(z, q, p);
      BigInteger r = BigInteger.ModPow(n, (q + 1) / 2, p);
      BigInteger t = BigInteger.ModPow(n, q, p);
      BigInteger m = ss;

      while (true)
      {
        if (t == 1)
        {
          return new ST_Solution(r, p - r, true);
        }
        BigInteger i = 0;
        BigInteger zz = t;
        while (zz != 1 && i < (m - 1))
        {
          zz = zz * zz % p;
          i = i + 1;
        }
        BigInteger b = c;
        BigInteger e = m - i - 1;
        while (e > 0)
        {
          b = b * b % p;
          e = e - 1;
        }
        r = r * b % p;
        c = b * b % p;
        t = t * c % p;
        m = i;
      }
    }


    /**
     * Computes the square root of a BigInteger modulo a prime employing the
     * Shanks-Tonelli algorithm.
     *
     * @param a value out of which we extract the square root
     * @param p prime modulus that determines the underlying field
     * @return a number <tt>b</tt> such that b<sup>2</sup> = a (mod p) if
     *         <tt>a</tt> is a quadratic residue modulo <tt>p</tt>.
     * @throws IllegalArgumentException if <tt>a</tt> is a quadratic non-residue modulo <tt>p</tt>
     */
    public static Org.BouncyCastle.Math.BigInteger ressol(Org.BouncyCastle.Math.BigInteger a, Org.BouncyCastle.Math.BigInteger p)

    {
      var ZERO = Org.BouncyCastle.Math.BigInteger.Zero;
      var ONE = Org.BouncyCastle.Math.BigInteger.One;
      var TWO = Org.BouncyCastle.Math.BigInteger.Two;

      Org.BouncyCastle.Math.BigInteger v = null;

      if (a.CompareTo(ZERO) < 0)
      {
        a = a.Add(p);
      }

      if (a.Equals(ZERO))
      {
        return ZERO;
      }

      if (p.Equals(TWO))
      {
        return a;
      }

      // p = 3 mod 4
      if (p.TestBit(0) && p.TestBit(1))
      {
        if (jacobi(a, p) == 1)
        { // a quadr. residue mod p
          v = p.Add(ONE); // v = p+1
          v = v.ShiftRight(2); // v = v/4
          return a.ModPow(v, p); // return a^v mod p
                                 // return --> a^((p+1)/4) mod p
        }
        throw new Exception("No quadratic residue: " + a + ", " + p);
      }

      long t = 0;

      // initialization
      // compute k and s, where p = 2^s (2k+1) +1

      Org.BouncyCastle.Math.BigInteger k = p.Subtract(ONE); // k = p-1
      long s = 0;
      while (!k.TestBit(0))
      { // while k is even
        s++; // s = s+1
        k = k.ShiftRight(1); // k = k/2
      }

      k = k.Subtract(ONE); // k = k - 1
      k = k.ShiftRight(1); // k = k/2

      // initial values
      Org.BouncyCastle.Math.BigInteger r = a.ModPow(k, p); // r = a^k mod p

      Org.BouncyCastle.Math.BigInteger n = r.Multiply(r).Remainder(p); // n = r^2 % p
      n = n.Multiply(a).Remainder(p); // n = n * a % p
      r = r.Multiply(a).Remainder(p); // r = r * a %p

      if (n.Equals(ONE))
      {
        return r;
      }

      // non-quadratic residue
      Org.BouncyCastle.Math.BigInteger z = TWO; // z = 2
      while (jacobi(z, p) == 1)
      {
        // while z quadratic residue
        z = z.Add(ONE); // z = z + 1
      }

      v = k;
      v = v.Multiply(TWO); // v = 2k
      v = v.Add(ONE); // v = 2k + 1
      Org.BouncyCastle.Math.BigInteger c = z.ModPow(v, p); // c = z^v mod p

      // iteration
      while (n.CompareTo(ONE) == 1)
      { // n > 1
        k = n; // k = n
        t = s; // t = s
        s = 0;

        while (!k.Equals(ONE))
        { // k != 1
          k = k.Multiply(k).Mod(p); // k = k^2 % p
          s++; // s = s + 1
        }

        t -= s; // t = t - s
        if (t == 0)
        {
          throw new Exception("No quadratic residue: " + a + ", " + p);
        }

        v = ONE;
        for (long i = 0; i < t - 1; i++)
        {
          v = v.ShiftLeft(1); // v = 1 * 2^(t - 1)
        }
        c = c.ModPow(v, p); // c = c^v mod p
        r = r.Multiply(c).Remainder(p); // r = r * c % p
        c = c.Multiply(c).Remainder(p); // c = c^2 % p
        n = n.Multiply(c).Mod(p); // n = n * c % p
      }
      return r;
    }


    // the jacobi function uses this lookup table
    private static int[] jacobiTable = { 0, 1, 0, -1, 0, -1, 0, 1 };

    /**
     * Computes the value of the Jacobi symbol (A|B). The following properties
     * hold for the Jacobi symbol which makes it a very efficient way to
     * evaluate the Legendre symbol
     * <p>
     * (A|B) = 0 IF gcd(A,B) &gt; 1<br>
     * (-1|B) = 1 IF n = 1 (mod 1)<br>
     * (-1|B) = -1 IF n = 3 (mod 4)<br>
     * (A|B) (C|B) = (AC|B)<br>
     * (A|B) (A|C) = (A|CB)<br>
     * (A|B) = (C|B) IF A = C (mod B)<br>
     * (2|B) = 1 IF N = 1 OR 7 (mod 8)<br>
     * (2|B) = 1 IF N = 3 OR 5 (mod 8)
     *
     * @param A integer value
     * @param B integer value
     * @return value of the jacobi symbol (A|B)
     */
    public static int jacobi(Org.BouncyCastle.Math.BigInteger A, Org.BouncyCastle.Math.BigInteger B)
    {
      var ZERO = Org.BouncyCastle.Math.BigInteger.Zero;
      var ONE = Org.BouncyCastle.Math.BigInteger.One;
      var TWO = Org.BouncyCastle.Math.BigInteger.Two;

      Org.BouncyCastle.Math.BigInteger a, b, v;
      long k = 1;

      k = 1;

      // test trivial cases
      if (B.Equals(ZERO))
      {
        a = A.Abs();
        return a.Equals(ONE) ? 1 : 0;
      }

      if (!A.TestBit(0) && !B.TestBit(0))
      {
        return 0;
      }

      a = A;
      b = B;

      if (b.SignValue == -1)
      { // b < 0
        b = b.Negate(); // b = -b
        if (a.SignValue == -1)
        {
          k = -1;
        }
      }

      v = ZERO;
      while (!b.TestBit(0))
      {
        v = v.Add(ONE); // v = v + 1
        b = b.Divide(TWO); // b = b/2
      }

      if (v.TestBit(0))
      {
        k = k * jacobiTable[a.IntValue & 7];
      }

      if (a.SignValue < 0)
      { // a < 0
        if (b.TestBit(1))
        {
          k = -k; // k = -k
        }
        a = a.Negate(); // a = -a
      }

      // main loop
      while (a.SignValue != 0)
      {
        v = ZERO;
        while (!a.TestBit(0))
        { // a is even
          v = v.Add(ONE);
          a = a.Divide(TWO);
        }
        if (v.TestBit(0))
        {
          k = k * jacobiTable[b.IntValue & 7];
        }

        if (a.CompareTo(b) < 0)
        { // a < b
          // swap and correct intermediate result
          Org.BouncyCastle.Math.BigInteger x = a;
          a = b;
          b = x;
          if (a.TestBit(1) && b.TestBit(1))
          {
            k = -k;
          }
        }
        a = a.Subtract(b);
      }

      return b.Equals(ONE) ? (int)k : 0;
    }

  }

  public class ST_Solution
  {
    private readonly BigInteger root1, root2;
    private readonly bool exists;

    public ST_Solution(BigInteger root1, BigInteger root2, bool exists)
    {
      this.root1 = root1;
      this.root2 = root2;
      this.exists = exists;
    }

    public BigInteger Root1()
    {
      return root1;
    }

    public BigInteger Root2()
    {
      return root2;
    }

    public bool Exists()
    {
      return exists;
    }
  }


}


