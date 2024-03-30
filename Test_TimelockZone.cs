using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TimeCryptor.Classes;
using static TimeCryptor.Test_TimelockZone;
using static TimeCryptor.Utils.BJJUtils;

namespace TimeCryptor
{
    public static class Test_TimelockZone
  {
    public enum CurveEnum
    {
      secp256k1,
      babyjubjub
    }

    public static void Run_Test_ValidationKeys()
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

      Test_TimeLockZone_KeyPair(timeLockZone.GetKeyPair(4893691)); //02 Round: 4893691(9 February 2024 14:14:00) - Baby Jubjub  --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4894031)); //03 Round: 4894031(9 February 2024 14:31:00) - Baby Jubjub --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4386431)); //Round: 4383771(22 January 2024 21:18:00) - Baby Jubjub    --> KO

      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(3139851)); //Round: 3139851; //(10 December 2023 16:42:00) - Secp256k1 --> OK
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(4893631)); //Round: 4893631(9 February 2024 14:11:00) - Secp256k1  -->OK

      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 4386431))} ===\n\n");


      //Test delle chiavi restituite dalla PoC di Iovino (scritto in C)
      //====================
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9016577));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9048294));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9068234));
      //Test_TimeLockZoneKeyPair(timeLockZone.GetKeyPair(9163298));
      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 9016577))} ===\n\n");
      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 9048294))} ===\n\n");
      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 9068234))} ===\n\n");
      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 9163298))} ===\n\n");

      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 4893631))} ===\n\n");
      Console.WriteLine($"=== {Test_TimelockZone_ECIES(timeLockZone.GetKeyPair(4893691))} ===\n\n");
      //Console.WriteLine($"=== {Test_TimelockZone_ECIES(listKeyPair.Single(s => s.Round == 4894031))} ===\n\n"); 
    }
    
    /// <summary>
    /// Controlla che la coppia di chiavi restituite dal servizio TimeLock.zone sia corretta la sk sia invertibile (ossi ala chiave derivata dalal privata sia corretta)
    /// </summary>
    /// <param name="kp">Coppia di chiavi (sk,PK)</param>
    private static void Test_TimeLockZone_KeyPair(KeyPairToCheck kp)
    {
      try
      {
        Console.WriteLine($"=== Coppia di chiavi in uso ===");
        Console.WriteLine($"PK: {kp.PublicKeyHex}");
        //Console.WriteLine($"PK W: {kp?.PublicKeyHexW}");
        Console.WriteLine($"SK: {kp.PrivateKeyHex}");
        Console.WriteLine($"Curve: {kp.Curve}");

        // if (!string.IsNullOrEmpty(kp.PublicKeyHexW)) var (x, y) = CryptoUtils.DecompressWeierStrassBjjKey(kp.PublicKeyHexW);

        var ecParameters = CryptoUtils.GetEcDomainParametersByCustomData(kp.Curve.ToString());

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
    private static bool Test_TimelockZone_ECIES(KeyPairToCheck kp)
    {
      var ret = false;
      try
      {
        Console.WriteLine($"=== Coppia di chiavi in uso ===");
        Console.WriteLine($"PK: {kp.PublicKeyHex}");
        Console.WriteLine($"PK W: {kp?.PublicKeyHexW}");
        Console.WriteLine($"SK: {kp.PrivateKeyHex}");
        Console.WriteLine($"Curve: {kp.Curve}");

        var isOriginalPkPointDecompressed = false;
        if (kp.PublicKeyHex.Substring(2, 2) == "04") isOriginalPkPointDecompressed = true;
        var publicKeyHex = kp.PublicKeyHex;
        if (kp.Curve == CurveEnum.babyjubjub)
        {
          //Conversion PK BJJ Twisted Edwards --> Weierstrass
          var point_TE = CryptoUtils.DecompressTwistedEdwardsBjjKey(publicKeyHex);
          var point_W = CryptoUtils.ConvertFromTwistedEdwardsToWeierstrass(point_TE.x, point_TE.y);
          publicKeyHex = CryptoUtils.CompressWeierstrassBjjPoint(point_W.x, point_W.y);
        }

        var ecParameters = CryptoUtils.GetEcDomainParametersByCustomData(kp.Curve.ToString());

        var ecPrivateKeyParamsD = new Org.BouncyCastle.Math.BigInteger(kp.PrivateKeyHex.Substring(2), 16);
        if (kp.Curve == CurveEnum.babyjubjub && isOriginalPkPointDecompressed) ecPrivateKeyParamsD = ecPrivateKeyParamsD.Mod(BJJDomainParameters_TE.l);
        var privateKeyParameters = new ECPrivateKeyParameters(ecPrivateKeyParamsD, ecParameters);

        byte[] publicKeyBytes = Hex.Decode(publicKeyHex.Substring(2));
        var publicKeyPoint = ecParameters.Curve.DecodePoint(publicKeyBytes);
        var publicKeyParameters = new ECPublicKeyParameters(publicKeyPoint, ecParameters);

        var keyPairRecipient = new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters);

        //ENCRYPT
        //Genera la coppia di chiavi del mittente
        var ecParams = CryptoUtils.GetEcDomainParametersByCustomData(kp.Curve.ToString());
        var keyPairSender = ECIES.GenerateECIESKeyPair(ecParams);
        //var skBytes = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPairSender.Private).ParsePrivateKey().GetDerEncoded();
        //var pkBytes = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPairSender.Public).GetDerEncoded();
        //Console.WriteLine($"pk effimera sender:\n{Convert.ToHexString(pkBytes)}"); ;
        //Console.WriteLine($"sk effimera sender:\n{Convert.ToHexString(skBytes)}");

        var message = "Ciao TLE!";
        var cipherText = ECIES.Encrypt(message, keyPairSender.Private, keyPairRecipient.Public);
        var cipherTextString = Convert.ToBase64String(cipherText);
        Console.WriteLine($"Testo originale: {message}");
        Console.WriteLine($"Testo cifrato: {cipherTextString}");

        //DECRYPT
        var plainText = ECIES.Decrypt(cipherText, keyPairSender.Public, keyPairRecipient.Private);
        Console.WriteLine($"Testo decifrato: {plainText}");

        ret = plainText == message;
      }
      catch (Exception ex)
      {
        ret = false;
        Console.WriteLine($"\nErrore: {ex.Message}");
      }
      return ret;
    }
  }
}
