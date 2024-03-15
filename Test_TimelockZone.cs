using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static TimeCryptor.Test_TimelockZone;

namespace TimeCryptor
{
  public static class Test_TimelockZone
  {
    public enum CurveEnum
    {
      secp256k1,
      babyjubjub,
      BLS12_381
    }

    public static void Run_TestKeys()
    {

      var timeLockZone = new TimeLockZone();

      //Test delle chiavi restituite dal servizio TimeLock.Zone(alpha) di AragonZK                                       Parametri Iovino           Parametri Aragon
      //=============================
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2849811)); //02 Round: 2849811 (30 November 2023 15:00:00) - Baby Jubjub --> Invalid Point            --> PK derivata corretta
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2429811)); //02 Round: 2429811 (16 November 2023 01:00:00) - Baby Jubjub --> No quadratic residue     --> Invalid Point
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2912211)); //03 Round: 2912211 (02 December 2023 19:00:00) - Baby Jubjub --> No quadratic residue     --> Invalid Point
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2911011)); //03 Round: 2911011 (02 December 2023 18:00:00) - Baby Jubjub --> PK derivata non corretta --> Invalid Point
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2907411)); //02 Round: 2907411 (02 December 2023 15:00:00) - Baby Jubjub --> No quadratic residue     --> Invalid Point
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2829411)); //02 Round: 2829411 (29 November 2023 22:00:00) - Baby Jubjub --> No quadratic residue     --> Invalid Point 
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2799411)); //02 Round: 2799411 (28 November 2023 21:00:00) - Baby Jubjub --> Invalid Point            --> Invalid Point
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2161011)); //03 Round: 2161011 (06 November 2023 17:00:00) - Baby Jubjub --> Invalid Point            --> PK Derivata corretta
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(2205411)); //03 Round: 2205411 (08 November 2023 06:00:00) - Baby Jubjub                              --> Invalid Point

      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4893691)); //02 Round: 4893691(9 February 2024 14:14:00) - Baby Jubjub  --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4894031)); //03 Round: 4894031(9 February 2024 14:31:00) - Baby Jubjub --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4386431)); //Round: 4383771(22 January 2024 21:18:00) - Baby Jubjub    --> KO

      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(3139851)); //Round: 3139851; //(10 December 2023 16:42:00) - Secp256k1 --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4893631)); //Round: 4893631(9 February 2024 14:11:00) - Secp256k1  -->OK

      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 4386431))} ===\n\n");


      //Test delle chiavi restituite dal PoC di Iovino (scritto in C)
      //====================
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9016577));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9048294));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9068234));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9163298));
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 9016577))} ===\n\n");
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 9048294))} ===\n\n");
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 9068234))} ===\n\n");
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 9163298))} ===\n\n");

      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 4893631))} ===\n\n");
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 4893691))} ===\n\n");
      //Console.WriteLine($"=== {ECIESTest_BC(listKeyPair.Single(s => s.Round == 4894031))} ===\n\n"); 
    }
    
    /// <summary>
    /// Controlla che la coppia di chiavi restituite dal servizio TimeLock.zone sia corretta la sk sia invertibile (ossi ala chiave derivata dalal privata sia corretta)
    /// </summary>
    /// <param name="kp">Coppia di chiavi (sk,PK)</param>
    private static void Test_TimeLockZoneKeyPair(KeyPairToCheck kp)
    {
      try
      {
        Console.WriteLine($"=== Coppia di chiavi in uso ===");
        Console.WriteLine($"PK: {kp.PublicKeyHex}");
        //Console.WriteLine($"PK W: {kp?.PublicKeyHexW}");
        Console.WriteLine($"SK: {kp.PrivateKeyHex}");
        Console.WriteLine($"Curve: {kp.Curve}");

        // if (!string.IsNullOrEmpty(kp.PublicKeyHexW)) var (x, y) = CryptoUtils.DecompressWeierStrassBjjKey(kp.PublicKeyHexW);

        var ecParameters = CryptoUtils.ecDomainParametersDirect(kp.Curve.ToString());

        var isOriginalPkPointDecompressed = false;
        if (kp.PublicKeyHex.Substring(2, 2) == "04") isOriginalPkPointDecompressed = true;

        var publicKeyHex = kp.PublicKeyHex;

        if (kp.Curve == CurveEnum.babyjubjub)
        {
          //conversione PK BJJ twisted edwards form to Weierstrass form
          Console.WriteLine("\n=== Conversione di PK da Twisted Edwards a Weierstrass ===");
          var point_TE = CryptoUtils.DecompressTwistedEdwardsBjjKey(publicKeyHex);
          var point_W = CryptoUtils.ConvertFromTwistedEdwardsToWeierstrass(point_TE.x, point_TE.y);
          publicKeyHex = CryptoUtils.CompressWeierstrassBjjPoint(point_W.x, point_W.y);
        }

        if (kp.Curve == CurveEnum.secp256k1)
        {
          // Equazione della curva secp256k1 --> y^2 = x^3 + a*x + b
          var p = new Org.BouncyCastle.Math.BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
          var a = new Org.BouncyCastle.Math.BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
          var b = new Org.BouncyCastle.Math.BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
          //var segno_y = 1;
          //if (publicKeyHex.Substring(2, 2) == "02") segno_y = 1; else segno_y = -1;
          var x = new Org.BouncyCastle.Math.BigInteger(publicKeyHex.Substring(4), 16);
          var eq_right = x.ModPow(Org.BouncyCastle.Math.BigInteger.Three, p).Add(a.Multiply(x)).Add(b).Mod(p); // y^2
          var y = CryptoUtils.ressol(eq_right, p);
          if (y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p) != eq_right) { y = p.Subtract(y); }

          //var sqrt = CryptoUtils.ShankTonelliSqrtModP2(dx.ConvertToBigInteger(), p.ConvertToBigInteger());
          //var y = sqrt.ConvertToBigIntergerBC();

          //var sqrt = CryptoUtils.ShankTonelliSqrtModP(dx.ConvertToBigInteger(), p.ConvertToBigInteger());
          //if (!sqrt.Exists()) throw new Exception("radice quadrata non trovata!");
          //var y = sqrt.Root1().ConvertToBigIntergerBC();
          //if (segno_y == -1) { y = sqrt.Root2().ConvertToBigIntergerBC(); } //y = y.Negate(); 

          var eq_left = y.ModPow(Org.BouncyCastle.Math.BigInteger.Two, p);
          var satisfy = (eq_left.CompareTo(eq_right) == 0);
          Console.WriteLine($"Il punto ({x},{y})  {(satisfy ? "è" : "NON è")} sulla curva.");
        }

        // Chiave PUBBLICA  
        var publicKeyString = publicKeyHex.Substring(2);
        byte[] publicKeyBytes = Hex.Decode(publicKeyString);
        var publicKeyPoint = ecParameters.Curve.DecodePoint(publicKeyBytes);

        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters("EC", publicKeyPoint, ecParameters);

        // Verifica della chiave pubblica
        bool isPublicKeyValid = publicKeyParameters.Q.IsValid();
        Console.WriteLine($"La chiave pubblica è {(isPublicKeyValid ? "valida" : "non valida")}.");

        // Chiave PRIVATA  
        var privateKeyString = kp.PrivateKeyHex.Substring(2);
        var privateKeyValue = new Org.BouncyCastle.Math.BigInteger(privateKeyString, 16);
        //if (kp.Curve == CurveEnum.babyjubjub && isOriginalPkPointDecompressed) { privateKeyValue = privateKeyValue.Mod(BJJDomainParameters_TE.l); }

        // Deriva la chiave pubblica    
        var derivedPublicKey = ecParameters.G.Multiply(privateKeyValue).Normalize();
        var derivedCompressedPublicKey = CryptoUtils.CompressWeierstrassBjjPoint(derivedPublicKey.XCoord.ToBigInteger(), derivedPublicKey.YCoord.ToBigInteger());
        Console.WriteLine($"derivedCompressedPublicKey {derivedCompressedPublicKey}");

        var derivedPublicKeyParameters = new ECPublicKeyParameters("EC", derivedPublicKey, ecParameters);
        var pString = derivedPublicKey.ToString();
        Console.WriteLine($"derivedPublicKey {pString}");


        // Verifica che la chiave pubblica derivata sia uguale a quella fornita
        bool arePublicKeysEqual = derivedPublicKeyParameters.Q.Equals(publicKeyParameters.Q);
        Console.WriteLine($"La chiave pubblica derivata è {(arePublicKeysEqual ? "corretta" : "NON corretta")}.");

      }
      catch (Exception ex)
      { 
        Console.WriteLine($"Errore: {ex.Message}");

      }
    }
  }

  public class TimeLockZone
  {
    List<KeyPairToCheck> listKeyPair = new List<KeyPairToCheck>();
    public TimeLockZone()
    {
      //=== Secp256k1 ===
      //================= 
      #region Chiavi Secp256k1 generate dal servizio TimeLock.Zone https://www.timelock.zone/nouns-demo.html funzionanti

      var id = 1;
      var keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.secp256k1 };
      //Round: 3139851; //(10 December 2023 16:42:00) - Secp256k1
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 3139851;
      keyPairToCheck.PublicKeyHex = "0x027e0dbea527ff8ba61a86853ac33c87a4388971e16fd70692d42c6b982d585e12";
      keyPairToCheck.PrivateKeyHex = "0XD4B81FA96E889EDCF7505890D0D7FFC5963D351021C7F1B11E028CE6EF08D592";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2703411 (25 November 2023 13:00:00) - Secp256k1
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.secp256k1 };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2703411;
      keyPairToCheck.PublicKeyHex = "0x036dee8461f1becfc2d88aa68acd48cc098f0eb4494551a9868820f0b702435ed4";
      keyPairToCheck.PrivateKeyHex = "0XCC5A09D05B8B545F817560DC083C6F2447C2456ED11E299F42425189A2FEC45D";
      listKeyPair.Add(keyPairToCheck);

      //Round: 4893631(9 February 2024 14:11:00) - Secp256k1
      //PK: 0x022e16a999dc784d4c3b9f786d20dec15b0e3adb583a1eda177ec2d8eefdf9d736
      //SK: 0X2F7FCBA63FBCF4AD9B782ADA24AD7D3984B4275B3FCACC8ECDF89C3A6C4C543A
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.secp256k1 };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 4893631;
      keyPairToCheck.PublicKeyHex = "0x022e16a999dc784d4c3b9f786d20dec15b0e3adb583a1eda177ec2d8eefdf9d736";
      keyPairToCheck.PrivateKeyHex = "0X2F7FCBA63FBCF4AD9B782ADA24AD7D3984B4275B3FCACC8ECDF89C3A6C4C543A";
      listKeyPair.Add(keyPairToCheck);
      #endregion

      // === BaByJubJub ===
      //===================
      #region Chiavi BJJ generate dal PoC di TLCS di Iovino su Git

      //  chiave generata dal codice TLCS di test di Iovino su Git
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 9016577;
      keyPairToCheck.PublicKeyHex = "0X0426B71C59EF0179D7E4FB6CBBB95AA335332FAFDEA421577EADEA1D6CD99FF8192D14CF55E2C63252599CD0E1376F0A66EACCBDA3747D7A7BE10B4FCE26816453";
      keyPairToCheck.PublicKeyHexW = "0X030450D6A7C6B0BF9BEA5155396668DAEB14F5FDC212EE08DF8A37D703509092EE"; //(versione compressa in Weirstrass)
      keyPairToCheck.PrivateKeyHex = "0X0B7B44A583C5506E118CD2A415F9857B3E1EE527B69D368C62A6D18DFF0C4101";
      listKeyPair.Add(keyPairToCheck);

      //  chiave generata dal codice TLCS di test di Iovino su Git
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 9048294;
      keyPairToCheck.PublicKeyHex = "0X041681EE9C1763E7DBD5181D160CE682B668CB7190546D910EA515B60EB456E9831EF53A074FBC27CE671AEEEC7D864BAA4701A988C7285770AC623A91D69E08FC";
      keyPairToCheck.PublicKeyHexW = "0X022C3AB74C62A370DBE12EAEBB50B6CA5B8D57F7CD311C2AE86E3D728FD0AC97AC"; //(versione compressa in Weirstrass)
      keyPairToCheck.PrivateKeyHex = "0X0AF12B4199F4F5190B70F86D250BD9FE8223A2BB3566ED06C842CA43C8E7571F";
      listKeyPair.Add(keyPairToCheck);

      //  chiave generata dal codice TLCS di test di Iovino su Git
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 9068234;
      keyPairToCheck.PublicKeyHex = "0X0417EBB22F39D110CABB9612BD9B187D06E4259C0EBFB6F47CD3F4CE462AF7ACB1055C4A044121ECB25957075C1A7BFA18F899D3252B483A9679A497DA440501BC";
      keyPairToCheck.PublicKeyHexW = "0x022B2FAC4AF71B148FB3797E0A5D0DFA7FB76EB64CA4BB3433243104611F47E812";  //(versione compressa in Weirstrass)
      keyPairToCheck.PrivateKeyHex = "0X860883DDAAF712CE12213C2ACA6ACE6EFCB2332ADE0E272F231E8A96C7FCEB";
      listKeyPair.Add(keyPairToCheck);

      //  chiave generata dal codice TLCS di test di Iovino su Git
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 9163298;
      keyPairToCheck.PublicKeyHex = "0X04262EAA3FA42056F95FB8025DAB77FE5E19C76DBDCABE47B512FAB6ACB6B6724B29E84243BC51B9DCE194C18E709AC50679DC8E782841DB40DEC978FD4D2319E9";
      keyPairToCheck.PublicKeyHexW = "0x03017E1E0791E012FC2CD18AAA4D23E6BDA1A92FA6845C731F3159D6CAB78B68EE";  //(versione compressa in Weirstrass)
      keyPairToCheck.PrivateKeyHex = "0X217C64192418EF7D9F9CB0750CB3F4E8CFDBB73363C7983EBEEB8BDC8AC0624F";
      listKeyPair.Add(keyPairToCheck);
      //Aggregate public key: 04262EAA3FA42056F95FB8025DAB77FE5E19C76DBDCABE47B512FAB6ACB6B6724B29E84243BC51B9DCE194C18E709AC50679DC8E782841DB40DEC978FD4D2319E9 03017E1E0791E012FC2CD18AAA4D23E6BDA1A92FA6845C731F3159D6CAB78B68EE
      //Successfully inverted sk 217C64192418EF7D9F9CB0750CB3F4E8CFDBB73363C7983EBEEB8BDC8AC0624F
      #endregion

      #region chiavi BJJ da servizio TimeLock.zone 
      //Round: 2849811(30 November 2023 15:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2849811;
      keyPairToCheck.PublicKeyHex = "0x02133fe928dee533a6eb455a5105e04a1361fe89598dcb32c24026c72c838832db";
      keyPairToCheck.PrivateKeyHex = "0X46C1A6BAE297E7B0469E75BD8DB6E10928CFCD4FD8810B0F14CC4DB8B9CA106";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2429811 (16 November 2023 01:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2429811;
      keyPairToCheck.PublicKeyHex = "0x020b4bf84e24a1b59114a438b6cd72367c615cb573ac62bf6821f75d57d59e3e46";
      keyPairToCheck.PrivateKeyHex = "0X2966AD36AAA60AEEC783DE60F32D60817ED1FED0A908D1DFEEB8919DCF7CB6F";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2912211 (2 December 2023 19:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2912211;
      keyPairToCheck.PublicKeyHex = "0x031b17b2751ba9d664a9e4583bce64debdf56d76580f77e7ce9e8ca09fa6ce6973";
      keyPairToCheck.PrivateKeyHex = "0X483E50B62D97CE4025349839947BFB87F1C99AC2B5B43976C7A5E5D88940EE5";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2911011 (2 December 2023 18:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2911011;
      keyPairToCheck.PublicKeyHex = "0x0317ca764e008f3af5b9376c5b3ac128e90f45dfce73307de2f33048d5575d7c9e";
      keyPairToCheck.PrivateKeyHex = "0X5B515B24B756A31495FBFEB68A49C25A25A074112A1E9D70DFB8F438BD0D562";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2907411 (2 December 2023 15:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2907411;
      keyPairToCheck.PublicKeyHex = "0x0203a0a6d4e698209706267248a3ca40b50e6ec9445b93e6c2f06c63b0e1d8034f";
      keyPairToCheck.PrivateKeyHex = "0X34A763603A1D25A8C4E17536DE61495C0A738724655BA2C1EB9320FA3BC80AC";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2829411 (29 November 2023 22:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2829411;
      keyPairToCheck.PublicKeyHex = "0x022443f368c2f375151b8b060e798d7ca0866ef1b137471b44179b67489bf7d1ae";
      keyPairToCheck.PrivateKeyHex = "0X2C8A7BE0ED97C9460EF5058C2247C878156E87AFC64BA62D8AD7A33E93CA1BD";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2799411 (28 November 2023 21:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2799411;
      keyPairToCheck.PublicKeyHex = "0x021156e19bed828f90e6a647c2074bf86354f4ec72fa9a3d5e76a91ab14f6df3f6";
      keyPairToCheck.PrivateKeyHex = "0X378994DD0B332679EA2F51D58A8F18AB4E1DEBF6364DE85FE57B17390B7B01F";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2161011(6 November 2023 17:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2161011;
      keyPairToCheck.PublicKeyHex = "0x03ade94079dc83b77f8e96c253bdb713c532546bd695c1e254210a5e4f4e37e83";
      keyPairToCheck.PrivateKeyHex = "0X47B72AA19BA9DE034AAF8F63ECF7EA51216F3D3F3325A7FC39CF8B736D73D14";
      listKeyPair.Add(keyPairToCheck);
      //Round: 2205411(8 November 2023 06:00:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 2205411;
      keyPairToCheck.PublicKeyHex = "0x03c98916b1daf5420cda008833fbbc7c769f532a9c0fb509a5d65ccd91f3e09ad";
      keyPairToCheck.PrivateKeyHex = "0X2915817686AEC1E012BA04EEB868A6F5D62BA0CE7F0AF6F18C933E9EBCD2E8D";
      listKeyPair.Add(keyPairToCheck);

      //Round: 4383771(22 January 2024 21:18:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 4383771;
      keyPairToCheck.PublicKeyHex = "0x022e6f5b5af695214a3fc0ababd03f3e28efb8da26baf461bcfaa3b7d18f4b543b";
      keyPairToCheck.PrivateKeyHex = "0X2A0791B1BDFC8405F4C43B2B9EF3227354945DFEF89E7A199BE263F4E856C75";
      listKeyPair.Add(keyPairToCheck);

      //Round: 4386431(22 January 2024 23:31:00) - Baby Jubjub
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 4386431;
      keyPairToCheck.PublicKeyHex = "0x02280511f47f149bb5d113f62107cef1aaa97d5be5b5ac4a777743420acdeeee07";
      keyPairToCheck.PrivateKeyHex = "0XAAB2298B277BB96C2E66F4F035699D8FC2E49E03AEBDF07CD8846F2C6693A1";
      listKeyPair.Add(keyPairToCheck);

      //Round: 4893691(9 February 2024 14:14:00) - Baby Jubjub
      //PK:0x020026c13ee24ef489cb62ffe1e09e14cc51f04fb8522102dfc47bc12f5b5cc6f5
      //SK: 0X3150AE2F0B8A0B47BDB4458A5807D283C0DFA64ED2130BBB729BE270C1AAEDC
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 4893691;
      keyPairToCheck.PublicKeyHex = "0x020026c13ee24ef489cb62ffe1e09e14cc51f04fb8522102dfc47bc12f5b5cc6f5";
      keyPairToCheck.PrivateKeyHex = "0X3150AE2F0B8A0B47BDB4458A5807D283C0DFA64ED2130BBB729BE270C1AAEDC";
      listKeyPair.Add(keyPairToCheck);

      //Round: 4894031(9 February 2024 14:31:00) - Baby Jubjub
      //PK:0x0329bd8de9fd183cd1d3661c167116c9a4a7004f2ae4c4b929101f669c5a320efb
      //SK: 0X31BDF3FABB409251CA41F34A37A541DBFFDCBFDE7E0A44DE0D8065A13CD6ECC
      keyPairToCheck = new KeyPairToCheck() { Curve = CurveEnum.babyjubjub };
      keyPairToCheck.Id = id++;
      keyPairToCheck.Round = 4894031;
      keyPairToCheck.PublicKeyHex = "0x0329bd8de9fd183cd1d3661c167116c9a4a7004f2ae4c4b929101f669c5a320efb";
      keyPairToCheck.PrivateKeyHex = "0X31BDF3FABB409251CA41F34A37A541DBFFDCBFDE7E0A44DE0D8065A13CD6ECC";
      listKeyPair.Add(keyPairToCheck);

      #endregion
    }
    public KeyPairToCheck GetKeyPair(int round)
    {
      return listKeyPair.Single(s => s.Round == round);
    }
  }
  public class KeyPairToCheck
  {
    public int Id { get; set; }
    public int Round { get; set; }
    public string PublicKeyHex { get; set; } //Twisted Edwards Form
    public string PublicKeyHexW { get; set; } //Weierstrass Form
    public string PrivateKeyHex { get; set; }
    public CurveEnum Curve { get; set; }
  }
}
