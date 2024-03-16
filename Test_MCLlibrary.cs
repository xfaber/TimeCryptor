using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace TimeCryptor
{
  internal class Test_MCLlibrary
  {

    static int err = 0;
    static void assert(string msg, bool b)
    {
      if (b) return;
      Console.WriteLine("ERR {0}", msg);
      err++;
    }
    public static void Run_TestPairing_BLS12_381()
    {
      Init(BLS12_381);

      var t = new Fr();
      t.SetByCSPRNG();

      Console.WriteLine("TestPairing");
      G1 P = new G1();
      P.HashAndMapTo("123");
      G2 Q = new G2();
      Q.HashAndMapTo("1");
      Fr a = new Fr();
      Fr b = new Fr();
      a.SetStr("12345678912345673453", 10);
      b.SetStr("230498230982394243424", 10);
      G1 aP = new G1();
      G2 bQ = new G2();
      aP.Mul(P, a);
      bQ.Mul(Q, b);
      GT e1 = new GT();
      GT e2 = new GT();
      GT e3 = new GT();
      e1.Pairing(P, Q);   //e(P,Q)
      e2.Pairing(aP, Q);  //e(aP,Q) 
      e3.Pow(e1, a);      //e(P,Q)^a
      assert("e2.Equals(e3)", e2.Equals(e3)); // e(aP,Q) == e(P,Q)^a
      e2.Pairing(P, bQ);  //e(P,bQ)
      e3.Pow(e1, b);      //e(P,Q)^b
      assert("e2.Equals(e3)", e2.Equals(e3)); //e(P,bQ) == e(P,Q)^b

      e2.Pairing(aP, bQ); //e(aP,bQ)
      Fr ab = new Fr();
      ab.Mul(a, b);
      e3.Pow(e1, ab);      //e(P,Q)^ab
      assert("e2.Equals(e3)", e2.Equals(e3));

      if (err == 0)
      {
        Console.WriteLine("all tests succeed");
      }
      else
      {
        Console.WriteLine("err={0}", err);
      }
    }


    public static void Run_TestSerialization() 
    {

      //Test di una firma BLS
      Init(BLS12_381);
      ETHmode();

      //var round = LeagueOfEntropy.GetRound(DateTime.Now);
      var round = 5928395;
      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);

      //sceglie una chiave privata casuale
      var sk = new Fr();
      sk.SetByCSPRNG();

      //genera la chiave pubblica su G2 con la chiave privata casuale scelta 
      var pk = new G2(); //Zp
      pk.Mul(g2, sk);

      //firma il messaggio s = sk H(msg)
      var bi_round = new BigInteger(round.ToString(), 10);
      var bytes_Round = bi_round.ToByteArray();
      var h = new G1();
      h.HashAndMapTo(bytes_Round);
      var sigma = new G1();
      sigma.Mul(h, sk);

      var e1 = new GT();
      e1.Pairing(sigma, g2);

      var e2 = new GT();
      e2.Pairing(h, pk);

           
      var verificaFirma = e1.Equals(e2);
      Console.WriteLine($"verifica firma: {verificaFirma} ");


      var sigma2 = new G1();
      var ser = sigma.Serialize();      
      sigma2.Deserialize(ser);
      var chk = sigma.Equals(sigma2);
      Console.WriteLine($"sigma==sigma2: {chk}");


      Console.WriteLine($"round : {round}");
      var sigma3 = new G1();
      var sigmaHexString = sigma.ToCompressedPoint();
      sigma3.Deserialize(CryptoUtils.FromHexStr(sigmaHexString));
      chk = sigma.Equals(sigma3);
      Console.WriteLine($"sigma : {sigmaHexString}");
      Console.WriteLine($"sigma3: {sigma3.ToCompressedPoint()}");      
      Console.WriteLine($"sigma==sigma3: {chk}");

      var pk2 = new G2();
      var pkHexString = pk.ToCompressedPoint();
      pk2.Deserialize(CryptoUtils.FromHexStr(pkHexString));
      chk = pk.Equals(pk2);
      Console.WriteLine($"pk : {pkHexString}");
      Console.WriteLine($"pk2: {pk2.ToCompressedPoint()}");
      Console.WriteLine($"pk==pk2: {chk}");
    }

    public static void RunTest_CheckFirmaLOE() 
    {
      //Test di una firma BLS
      Init(BLS12_381);
      ETHmode();

      //Generate da LOE
      
      //bls-unchained-g1-rfc9380
      //var pkHexString = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
      //var sigmaString = "a5d07c0071b4e386b3ae09206522253c68fefe8490ad59ecc44a7dd0d0745be91da5779e2247a82403fbc0cb9a34cb61";
      //var round = 5928395;

      //bls-unchained-on-g1
      var pkHexString = "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13";
      var sigmaString = "82036f6bcd6f626ba4526edb9918a296877579707f49a494723d865d27d42d84dee9cce84a37c21fe6d365ad9fae75db";
      var round = 11775741;
       

      //generate da MCL
      //var pkHexString = "AE5462878CE369072BEC7690B59FC50AC6A082E4EE3116AFF0299E9BBFC0831783890366A3C1C181D1D0EB41826CB2611444E36D48ACC772AD345C73746DBD3BD807ACA3CAD993010D7CD0955B25A222D6245D84DF84D295FC7E310CEF974AD7";
      //var sigmaString = "A15FBA695765D9467C8F2CA46D57B9181822E305096A1ADFB0E4FF5F1964AD192F880201F99329580168E54A22596254";
      //var round = 5928395;


      var pkLOE = new G2();
      pkLOE.Deserialize(CryptoUtils.FromHexStr(pkHexString));
      Console.WriteLine($"pkLOE isValid: {pkLOE.IsValid()} ");
      Console.WriteLine($"pkLOE isZero: {pkLOE.IsZero()} ");
      
      var sigmaLOE = new G1();
      sigmaLOE.Deserialize(CryptoUtils.FromHexStr(sigmaString));
      Console.WriteLine($"sigmaLOE isValid: {sigmaLOE.IsValid()} ");
      Console.WriteLine($"sigmaLOE isZero: {sigmaLOE.IsZero()} ");
      
      var chk = checkFirma(round, sigmaLOE, pkLOE);
      Console.WriteLine($"verifica firma LOE: {chk} ");
    }

    public static bool checkFirma(int round, G1 sigma, G2 pk)
    {
      Init(BLS12_381);
      ETHmode();

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2();
      g2.SetStr(g2Str, 16);

      var bi_round = new BigInteger(round.ToString(), 10);
      var bytes_Round = bi_round.ToByteArray();
      var h = new G1();
      h.HashAndMapTo(bytes_Round);

      var e1 = new GT();
      e1.Pairing(sigma, g2);

      var e2 = new GT();
      e2.Pairing(h, pk);

      var retCheck = e1.Equals(e2);
      return retCheck;
    }

    public static void RunTest_SerializeDeserialize()
    {
      Init(BLS12_381);
      ETHmode();
      var now = DateTime.Now;
      Console.WriteLine($"Data corrente: {now.ToString("dd/MM/yyyy HH:mm:ss")} round:{LeagueOfEntropy.GetRound(now)}");
      var span = new TimeSpan(0,0,3);
      var futureDateTime = now.Subtract(span);
      var round = LeagueOfEntropy.GetRound(futureDateTime);
      Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");

      var LOE = new LeagueOfEntropy();
      LOE.CreateKeyPair(round);
      var sigmaLOE = LOE.GetSigma(round);
      while (sigmaLOE == null)
      {
        Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
        Thread.Sleep(1000);
        sigmaLOE = LOE.GetSigma(round);
      }

      var checkFirma = LeagueOfEntropy.checkFirma(round, (G1)sigmaLOE, (G2)LOE.pk);      
      Console.Write($"Firma LOE {(checkFirma?"valida":"NON valida")}");

      var sigmaLOE2 = new G1();
      sigmaLOE2.Deserialize(((G1)sigmaLOE).Serialize());
      var chk = sigmaLOE.Equals(sigmaLOE2);
      Console.WriteLine($"sigmaLOE==sigmaLOE2: {chk}");
      /*
      var sigmaLOEcompressed = sigmaLOE.ToCompressedPoint();
      Console.WriteLine($"sigmaLOE: {sigmaLOEcompressed.ToLower()}");
      var sigmaLOE2 = new G1();
      sigmaLOE2.SetStr(sigmaLOEcompressed, 16);
      var chk = sigmaLOE.Equals(sigmaLOE2);    
      */

    }
  }
}
