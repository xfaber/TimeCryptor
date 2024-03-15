using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;
namespace TimeCryptor
{
  public static class ECIES
  {
    //ECIES - Elliptic Curve Integrated Encryption Scheme

    public static AsymmetricCipherKeyPair GenerateECIESKeyPair(ECDomainParameters ecParams)
    {
      ECKeyPairGenerator gen = new ECKeyPairGenerator();
      SecureRandom secureRandom = new SecureRandom();

      //X9ECParameters ecps = CustomNamedCurves.GetByName(ecCurveName);
      //ECDomainParameters ecDomainParameters = new ECDomainParameters(ecps.Curve, ecps.G, ecps.N, ecps.H, ecps.GetSeed());
      //var ecDomainParameters = CryptoUtils.ecDomainParametersDirect(ecCurveName);
      ECKeyGenerationParameters ecKeyGenerationParameters = new ECKeyGenerationParameters(ecParams, secureRandom);
      gen.Init(ecKeyGenerationParameters);      
      var keyPair = gen.GenerateKeyPair(); 

      return keyPair;
    }

    /// <summary>
    /// Cifra un plaintext utilizzando lo schema ECIES con AES
    /// </summary>
    /// <param name="plaintext"></param>
    /// <param name="privateKeySender"></param>
    /// <param name="publicKeyRecipient"></param>
    /// <returns></returns>
    public static byte[] Encrypt(string plaintext, AsymmetricKeyParameter privateKeySender, AsymmetricKeyParameter publicKeyRecipient)
    {
      var d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }; //derivation
      var e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }; //encoding
      var macKeySize = 64;
      var cipherKeySize = 128;
      var p = new IesWithCipherParameters(d, e, macKeySize, cipherKeySize);

      // Encrypt      
      //new Org.BouncyCastle.Crypto.Generators.SCrypt()
      BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
      var cryptEng = new IesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha256Digest()), new HMac(new Sha256Digest()), cipher);
      cryptEng.Init(true, privateKeySender, publicKeyRecipient, p); //cryptEng.Init(true, Alice.Private, Bob.Public, p);
      byte[] data = Encoding.UTF8.GetBytes(plaintext);
      byte[] ciphertext = cryptEng.ProcessBlock(data, 0, data.Length);
      
      Console.WriteLine($"Plaintext: {plaintext}");
      //Console.WriteLine($"Ciphertext (hex): {BitConverter.ToString(ciphertext).Replace("-", "")}");

      //return cipherTextPublicKey, encryptedMessage, authTag
      
      return ciphertext; //contiene sia il testo cifrato che il tag hmac
    }

    public static string Decrypt(byte[] ciphertext, AsymmetricKeyParameter publicKeySender, AsymmetricKeyParameter privateKeyRecipient)
    {
      var d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
      var e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
      var p = new IesWithCipherParameters(d, e, 64, 128);

      // Decrypt
      BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
      var decryptEng = new IesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha256Digest()), new HMac(new Sha256Digest()), cipher);

      decryptEng.Init(false, privateKeyRecipient, publicKeySender, p);
      byte[] decryptedBytes = decryptEng.ProcessBlock(ciphertext, 0, ciphertext.Length);

      var p1 = new byte[decryptedBytes.Length];
      Buffer.BlockCopy(decryptedBytes, 0, p1, 0, decryptedBytes.Length);

      // Converti il testo decifrato in una stringa
      string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

      return decryptedText;
    }

  }
}
