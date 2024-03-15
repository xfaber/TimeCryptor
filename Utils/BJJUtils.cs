using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TimeCryptor.Utils
{
  public static class BJJUtils
  {
    public static (BigInteger x, BigInteger y) DecompressTwistedEdwardsBjjKey(string keyHex)
    {
      Console.WriteLine("=== DecompressTwistedEdwardsBjjKey ===");
      var zeroPad = "";
      for (int i = 0; i < 64 - keyHex.Substring(4).Length; i++)
      {
        zeroPad = zeroPad + "0";
      }
      if (keyHex.Substring(4).Length < 64) keyHex = keyHex.Insert(4, zeroPad); //.InsertChars('0', 4, 64 - keyHex.Substring(4).Length);

      var x_TE = new BigInteger(keyHex.Substring(4, 64), 16);

      BigInteger y_TE;
      var prefix = keyHex.Substring(2, 2);

      var p = BJJDomainParameters_TE.p;
      var a_TE = BJJDomainParameters_TE.a;
      var d_TE = BJJDomainParameters_TE.d;

      // Baby JubJub Twisted Edwards ax^2 + y^2 = 1 + dx^2y^2 ==>  calculate y from x ==> y = sqrt( (1 - a*x^2) / (1 - d*x^2) )
      var y_TE_num = BigInteger.One.Subtract(a_TE.Multiply(x_TE.ModPow(BigInteger.Two, p)).Mod(p)).Mod(p);
      var y_TE_den = BigInteger.One.Subtract(d_TE.Multiply(x_TE.ModPow(BigInteger.Two, p)).Mod(p)).Mod(p);
      y_TE = y_TE_den.ModInverse(p).Multiply(y_TE_num).Mod(p); // y^2
      Console.WriteLine($"Twisted Edwards (1 - a*x^2) / (1 - d*x^2)): {y_TE}");

      BigInteger sqrt;
      sqrt = CryptoUtils.ressol(y_TE, p); // Computes the square root of a BigInteger modulo a prime employing the Shanks-Tonelli algorithm.
      Console.WriteLine($"sqrt \n sqrt: {sqrt}");

      if (sqrt.ModPow(BigInteger.Two, p).CompareTo(y_TE) != 0) { y_TE = p.Subtract(sqrt); }
      else { y_TE = sqrt; }

      Console.WriteLine("\n=== Chiave PK - Twisted Edwards ===");
      Console.WriteLine($"publicKeyHex: {keyHex}");
      Console.WriteLine($"Punto ({x_TE}, {y_TE}).");

      CheckPointOnBjjCurveTwistedEdwards(x_TE, y_TE);

      return (x_TE, y_TE);
    }

    public static (BigInteger x, BigInteger y) ConvertFromTwistedEdwardsToWeierstrass(BigInteger x_TE, BigInteger y_TE)
    {
      //domain parameters JubJub
      var p = BJJDomainParameters_TE.p;

      // Conversion from Twisted Edwards to Montgomery is (x,y)->(X,Y)=((1+y)/(1-y),(1+y)/((1-y)x))
      var UnoPiuY = BigInteger.One.Add(y_TE).Mod(p);
      var UnoMenoY = BigInteger.One.Subtract(y_TE).Mod(p);
      var UnoMenoYX = UnoMenoY.Multiply(x_TE).Mod(p);
      var X = UnoMenoY.ModInverse(p).Multiply(UnoPiuY).Mod(p);
      var Y = UnoMenoYX.ModInverse(p).Multiply(UnoPiuY).Mod(p);

      //Montgomery By^2 = x^3 + Ax^2 + x      (se B=1) ==>  y^2 = x^3 + Ax^2 + x
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;

      //conversion from TE to MO A=2*(a+d)/(a-d) B=4/(a-d)
      var a_meno_d = BJJDomainParameters_TE.a.Subtract(BJJDomainParameters_TE.d).Mod(p);
      var a_piu_d = BJJDomainParameters_TE.a.Add(BJJDomainParameters_TE.d).Mod(p);
      var a2_MO = a_meno_d.ModInverse(p).Multiply(BigInteger.Two.Multiply(a_piu_d).Mod(p)).Mod(p);
      var b2_MO = a_meno_d.ModInverse(p).Multiply(BigInteger.Four).Mod(p);

      CheckPointOnBjjCurveMontgomery(X, Y);

      //https://en.wikipedia.org/wiki/Montgomery_curve
      // Conversion Montgomery to Weierstrass is (X, Y)->(x_W, y_W) = (X/B + A/3B, Y/B)
      var XsuB = b_MO.ModInverse(p).Multiply(X).Mod(p);
      var Asu3B = (BigInteger.Three.Multiply(b_MO).Mod(p)).ModInverse(p).Multiply(a_MO).Mod(p);
      var x_W = XsuB.Add(Asu3B).Mod(p);
      var y_W = b_MO.ModInverse(p).Multiply(Y).Mod(p);

      CheckPointOnBjjCurveWeierstrass(x_W, y_W);

      return (x_W, y_W);
    }

    public static string CompressWeierstrassBjjPoint(BigInteger x, BigInteger y)
    {
      //02: positive - 03: negative
      var segno_y_code = (y.TestBit(0) == false) ? "02" : "03";
      var x_hex = System.Numerics.BigInteger.Parse(x.ToString()).ToString("X");
      x_hex = "00000" + x_hex;
      x_hex = x_hex.Substring(x_hex.Length - 64, 64);
      var publicKeyHex = $"0x{segno_y_code}{x_hex}";

      Console.WriteLine("\n=== Chiave PK - Weierstrass ===");
      Console.WriteLine($"publicKeyHex: {publicKeyHex}");
      Console.WriteLine($"Punto ({x}, {y}).");

      return publicKeyHex;
    }

    public static bool CheckPointOnBjjCurveTwistedEdwards(BigInteger x, BigInteger y)
    {
      var ret = false;

      //domain parameters JubJub (twistded edwards form)
      var p = BJJDomainParameters_TE.p;
      var a_TE = BJJDomainParameters_TE.a;
      var d_TE = BJJDomainParameters_TE.d;

      var eq_left = a_TE.Multiply(x.ModPow(BigInteger.Two, p)).Mod(p).Add(y.ModPow(BigInteger.Two, p)).Mod(p);
      var eq_right = BigInteger.One
                     .Add(
                            d_TE.Multiply(x.ModPow(BigInteger.Two, p)).Mod(p)
                            .Multiply(y.ModPow(BigInteger.Two, p)).Mod(p)
                         ).Mod(p);
      ret = (eq_left.CompareTo(eq_right) == 0);
      Console.WriteLine($"Coordinate Twisted Edwards ({x},{y}) {(ret ? "è" : "NON è")} sulla curva.");

      return ret;
    }
    public static bool CheckPointOnBjjCurveWeierstrass(BigInteger x, BigInteger y)
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
      var a_num = BigInteger.Three.Subtract(a_MO.ModPow(BigInteger.Two, p)).Mod(p);
      var a_den = BigInteger.Three.Multiply(b_MO.ModPow(BigInteger.Two, p)).Mod(p);
      var a = a_den.ModInverse(p).Multiply(a_num).Mod(p);
      var nove = new BigInteger("9");
      var venti7 = new BigInteger("27");
      var b_num = BigInteger.Two.Multiply(a_MO.ModPow(BigInteger.Three, p)).Mod(p).Subtract(nove.Multiply(a_MO).Mod(p)).Mod(p);
      var b_den = venti7.Multiply(b_MO.ModPow(BigInteger.Three, p)).Mod(p);
      var b = b_den.ModInverse(p).Multiply(b_num).Mod(p);
      Console.WriteLine($"Parametri Weierstrass \na: {a} \nb: {b}");

      // y^2 = x^3+ax+b
      var sx = y.ModPow(BigInteger.Two, p);
      var dx = x.ModPow(BigInteger.Three, p).Add(a.Multiply(x).Mod(p)).Mod(p).Add(b).Mod(p);
      var satisfy = (sx.CompareTo(dx) == 0);
      Console.WriteLine($"Coordinate Weierstrass ({x},{y}) {(satisfy ? "è" : "NON è")} sulla curva.");

      return ret;
    }
    public static bool CheckPointOnBjjCurveMontgomery(BigInteger X, BigInteger Y)
    {
      var ret = false;
      //Montgomery By^2 = x^3 + Ax^2 + x (se B=1) ==>  y^2 = x^3 + Ax^2 + x
      var p = BJJDomainParameters_TE.p;
      var a_MO = BJJDomainParameters_M.a;
      var b_MO = BJJDomainParameters_M.b;
      var eq_left = b_MO.Multiply(Y.ModPow(BigInteger.Two, p)).Mod(p);
      var eq_right = X.ModPow(BigInteger.Three, p).Add(a_MO.Multiply(X.ModPow(BigInteger.Two, p))).Mod(p).Add(X).Mod(p);
      ret = (eq_left.CompareTo(eq_right) == 0);
      Console.WriteLine($"Coordinate Montgomery ({X},{Y}) {(ret ? "è" : "NON è")} sulla curva.");

      return ret;
    }
    public static class BJJDomainParameters_M
    {
      public static BigInteger a { get { return new BigInteger("168698"); } }
      //Parametri usati per le chiavi generate da stub Iovino su GitHub
      //public static BigInteger b { get { return BigInteger.One; } }

      //Parametri usati per le chiavi generate sul sito AragonZK
      public static BigInteger b { get { return new BigInteger("168700"); } }
    }

    /// <summary>
    /// Parametri della curv aBaby Jub Jub in forma Twisted Edwards
    /// </summary>
    public static class BJJDomainParameters_TE
    {
      /* Parameters values
        //Weierstrass Form (decimal)
        p:  21888242871839275222246405745257275088548364400416034343698204186575808495617
        n:  2736030358979909402780800718157159386076813972158567259200215660948447373041
        a:  3915561033734670630843635270522714716872400990323396055797168613637673095919
        b:  4217185138631398382466346491768379401896178114478749112717062407767665636606
        Gx: 4513000517330448244903653178865560289910339884906555605055646870021619219232
        Gy: 12354950672345577792670528317750261467336531611841695810091486319550864339243

        //Weierstrass Form (HEX)
        p:  30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
        n:  60C89CE5C263405370A08B6D0302B0BAB3EEDB83920EE0A677297DC392126F1
        a:  8A82106B27C1E0FB37494BEC36B159BC19F7F45DE5E5238F0A32C7A047E92EF
        b:  952D79A8C492EE6CC89534BD9D5F01A8C81B25C334E876BA4F27A03AD0374FE
        Gx: 9FA448CC4F5D590C574819640435AD007837590A218D8344F7FBD4FB0127B20
        Gy: 1B50A77E40C72B88B9C308BE70301CD773298BDF2E1E495095789887F264B12B
      */

      /* References 
      https://eips.ethereum.org/EIPS/eip-2494
      https://github.com/arkworks-rs/algebra/blob/master/curves/ed_on_bn254/src/curves/mod.rs
      https://github.com/arkworks-rs/algebra/blob/master/curves/ed_on_bn254/src/lib.rs
      */
      //Equazione della curva ax^2 + y^2 = 1 + dx^2y^2
      //La curva è definita su un campo primo finito di p elementi (con p numero primo)
      public static BigInteger p { get { return new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"); } }

      // mumero primo a 251 bit
      public static BigInteger l { get { return new BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041"); } }

      // cofattore
      public static BigInteger h { get { return new BigInteger("8"); } }

      public static BigInteger n { get { return new BigInteger("21888242871839275222246405745257275088614511777268538073601725287587578984328"); } }

      //Generator Point G
      //Il punto G=(x,y) che genera tutti gli n punti della curva
      public static BigInteger Gx { get { return new BigInteger("995203441582195749578291179787384436505546430278305826713579947235728471134"); } }
      public static BigInteger Gy { get { return new BigInteger("5472060717959818805561601436314318772137091100104008585924551046643952123905"); } }

      //Parametri usati per le chiavi generate sul sito AragonZK
      //https://github.com/arkworks-rs/algebra/blob/master/curves/ed_on_bn254/src/lib.rs
      public static BigInteger a { get { return new BigInteger("1"); } }
      public static BigInteger d { get { return new BigInteger("9706598848417545097372247223557719406784115219466060233080913168975159366771"); } }
      public static BigInteger Bx { get { return new BigInteger("19698561148652590122159747500897617769866003486955115824547446575314762165298"); } }
      public static BigInteger By { get { return new BigInteger("19298250018296453272277890825869354524455968081175474282777126169995084727839"); } }

    }
  }
}
