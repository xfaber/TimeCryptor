using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;

namespace TimeCryptor
{
  public static class PoC_Tlock
  {
    public static void Run_PoC()
    {
      Run_Test_EncDecBLSonG1();
    }

    public static void Run_Test_EncDecBLSonG1()
    {
      #region PK su G2 e FirmaBLS su G1
      /*
      https://pl-eu.testnet.drand.sh/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/info
      {
          "public_key": "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13",
          "period": 3,
          "genesis_time": 1675262550,
          "hash": "f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c",
          "groupHash": "73c191da8ca22628987bc9fb330e2b82f9e38728a8708b10b42b43c90643b798",
          "schemeID": "bls-unchained-on-g1",
          "metadata": {"beaconID": "testnet-g" }
      }
      https://pl-eu.testnet.drand.sh/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/public/latest
      {
          "round": 11064067,
          "randomness": "4a8ff98e685c0acf9284b7226ffd740d0dc1be990a2e5fe4b51778ba2b2f6977",
          "signature": "b413cddd656559eaddcc5b1bf6e55f842b4cf878a1bf315e60e3b9693f57e2397ff63d5dc9c76f464cbaf536c9fdf752"
      }
      */

      /*
      {
        "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
        "period": 3,
        "genesis_time": 1692803367,
        "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
        "schemeID": "bls-unchained-g1-rfc9380",
        "metadata": {"beaconID": "quicknet"}
      }
      {
        "round": 5358915,
        "randomness": "ded576cc39a412bc7c66c6f4a530983f4894567ed27846fcca14909436308814",
        "signature": "95f058cbd1294bc3fa28647dabded06d50b543643fb04e1cb2c5b6204daf20935782f7cae5fa7718cf87b4c43d108842"
      }
      */
      ulong round = 5358915;
      var PKLOEstring = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
      var sigLOEstring = "95f058cbd1294bc3fa28647dabded06d50b543643fb04e1cb2c5b6204daf20935782f7cae5fa7718cf87b4c43d108842";

      var cipherText = Encrypt_BLSonG1(round, PKLOEstring);
      var decipherText = Decrypt_BLSonG1(cipherText, sigLOEstring);

      #endregion
    }
    public static void Run_Test_EncDecBLSonG2()
    {
      #region PK su G1 e FirmaBLS su G2 
      /*
      https://pl-eu.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/info
       {
        "public_key": "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
        "period": 3,
        "genesis_time": 1651677099,
        "hash": "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
        "groupHash": "65083634d852ae169e21b6ce5f0410be9ed4cc679b9970236f7875cff667e13d",
        "schemeID": "pedersen-bls-unchained",
        "metadata": { "beaconID": "testnet-unchained-3s" }
      }

      https://pl-eu.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/latest
      {
        "round": 18925798,
        "randomness": "06734eb4fd6446ad313a1b6bc2aaeb4a5e3c58ad820a96535ad3e4253a846486",
        "signature": "adb9c7c781edc13a5a48e0887b23cc33f4164cb715967b0d11d518980c564eefe7a6a44c5d1c7d2158b20f75fc5bf35507bafd20b355abc62443c01e6343c2574435e4ef437ca07cfa946cdd2537dc76aa3b9af6c718561089462f6a2bae6189"
      }
      */
      #endregion

      ulong round = 18925798;
      var PKLOEstring = "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11";
      var sigLOEstring = "adb9c7c781edc13a5a48e0887b23cc33f4164cb715967b0d11d518980c564eefe7a6a44c5d1c7d2158b20f75fc5bf35507bafd20b355abc62443c01e6343c2574435e4ef437ca07cfa946cdd2537dc76aa3b9af6c718561089462f6a2bae6189";

      var cipherText = Encrypt_BLSonG2(round, PKLOEstring);
      var decipherText = Decrypt_BLSonG2(cipherText, sigLOEstring);
    }

    public static byte[] GetSHA256(byte[] aBytes)
    {
      var H = new Sha256Digest();
      H.BlockUpdate(aBytes, 0, aBytes.Length);
      var hash = new byte[H.GetDigestSize()];
      H.DoFinal(hash, 0);
      return hash.Reverse().ToArray();
    }
    public static BigInteger H3(byte[] a, byte[] b)
    {
      var pref = System.Text.Encoding.UTF8.GetBytes("IBE-H3");
      IEnumerable<byte> rv = pref.Concat(a).Concat(b);
      var h3ret = GetSHA256(rv.ToArray());

      // We will hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
      // value that is suitable as a scalar.
      var BitsToMaskForBLS12381 = 1;
      for (var i = 1; i < 65535; i++)
      {
        var data = h3ret;
        //byte[] ibytes = BitConverter.GetBytes(i);
        byte[] ibytes = new BigInteger(i.ToString(), 10).ToByteArray();
        data = GetSHA256(ibytes.Concat(data).ToArray());
        data[0] = (byte)(data[0] >> BitsToMaskForBLS12381); //shift a destra di 1 byte del byte 0
        //if (BitConverter.IsLittleEndian) Array.Reverse(data);
        var n = new BigInteger(data);
        var r = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
        if (n.CompareTo(r) < 0) return n;
      }
      throw new Exception("invalid proof: rP check failed");
    }

    public static (G1 U, BigInteger V, BigInteger W) Encrypt_BLSonG2(ulong round, string PKLOEstring)
    {
      Init(BLS12_381);
      ETHmode();
      G2setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
      
      var rbytes_le = BitConverter.GetBytes(round);   //--> little-endian
      var rbytes_be = rbytes_le.Reverse().ToArray();  //--> big-endian
      var rHash = CryptoUtils.GetSHA256(rbytes_be);
      var HC = new G2();
      HC.HashAndMapTo(rHash); //H1(C)      
      Console.WriteLine($"HC: {HC.GetStr(16)}");

      mclBn_setETHserialization(1);
      var bytes_pkloe = CryptoUtils.FromHexStr(PKLOEstring);
      var PKLOE = new G1();
      PKLOE.Deserialize(bytes_pkloe);
      if (!PKLOE.IsValid()) throw new Exception("PKLOEstring not valid!");
      Console.WriteLine($"PKLOE: {PKLOE.GetStr(16)}");
      mclBn_setETHserialization(0);

      var Gid = new GT();
      Gid.Pairing(PKLOE, HC);

      var messaggio = "Ciao Ali";
      var sigma = CryptoUtils.GetSecureRandomNumber(messaggio.Length * 8).ConvertToBigIntergerBC();
      var bytes_sigma = sigma.ToByteArray();
      var M = System.Text.Encoding.UTF8.GetBytes(messaggio); //  il messaggio deve essere max 256 bit (lunghezza massima dell'hash SHA256)
      var h3 = H3(bytes_sigma, M);
      var bytes_h3 = h3.ToByteArray();

      mclBn_setETHserialization(1);
      var g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
      var g1 = new G1(); //Zp
      g1.SetStr(g1Str, 16);
      if (!g1.IsValid()) throw new Exception("g1 not valid!");
      mclBn_setETHserialization(0);
      var U = new G1();
      var r = new Fr();
      r.Deserialize(bytes_h3);
      if (!r.IsValid()) throw new Exception("r is not valid!");
      U.Mul(g1, r);
      if (!U.IsValid()) throw new Exception("U is not valid!");

      var Gid_pow_r = new GT();
      Gid_pow_r.Pow(Gid, r);
      var h2 = GetSHA256(Gid_pow_r.Serialize());
      var bi_h2 = new BigInteger(h2);
      var V = sigma.Xor(bi_h2);

      var bi_M = new BigInteger(M);
      var h4 = GetSHA256(sigma.ToByteArray());
      var bi_h4 = new BigInteger(h4);
      var W = bi_M.Xor(bi_h4);
      return (U, V, W);
    }
    public static string Decrypt_BLSonG2((G1 U, BigInteger V, BigInteger W) cipherText, string sigLOEstring)
    {
      Init(BLS12_381);

      // Calcola sigma' = V xor H2(e(U,sigLOE))      
      var SigLOE = new G2();
      mclBn_setETHserialization(1);
      var bytes_SKLOE = CryptoUtils.FromHexStr(sigLOEstring);
      SigLOE.Deserialize(bytes_SKLOE);
      if (!SigLOE.IsValid()) throw new Exception("SigLOEstring not valid!");
      mclBn_setETHserialization(0);
      var e = new GT();
      e.Pairing(cipherText.U, SigLOE);
      var H2 = GetSHA256(e.Serialize());
      var bi_H2 = new BigInteger(H2);
      var sigma = cipherText.V.Xor(bi_H2);
      var bytes_sigma = sigma.ToByteArray();

      //Calcola M' = W XOR H4(sigma')
      var H4 = GetSHA256(bytes_sigma);
      var bi_H4 = new BigInteger(H4);
      var M = cipherText.W.Xor(bi_H4);
      var bytes_M = M.ToByteArray();

      //r' = H3(sigma',M')
      var bi_r = H3(bytes_sigma, bytes_M);
      var bytes_r = bi_r.ToByteArray();
      var r = new Fr();
      r.Deserialize(bytes_r);
      if (!r.IsValid()) throw new Exception("r not valid!");

      // check U == r'G1
      var g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
      mclBn_setETHserialization(1);
      var g1 = new G1();
      g1.SetStr(g1Str, 16);
      if (!g1.IsValid()) throw new Exception("g1 not valid!");
      mclBn_setETHserialization(0);
      var U = new G1();
      U.Mul(g1, r);
      if (U.Equals(cipherText.U)) return System.Text.Encoding.UTF8.GetString(bytes_M);
      else return "ERROR!";
    }

    public static (G2 U, BigInteger V, BigInteger W) Encrypt_BLSonG1(ulong round, string PKLOEstring)
    {
      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      /*
      var SigLOEString = "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0";
      var bytes_test = FromHexStr(SigLOEString);
      var sha256_SigLOE = GetSHA256(bytes_test);
      var bi_shatest = new BigInteger(sha256_SigLOE);
      var sha256_SigLOEString = CryptoUtils.ConvertToBigInteger(bi_shatest).ToString("x2");
      Console.WriteLine($"SHA256 {sha256_SigLOEString==randomness}");
      */

      //Calcola H1(Sha256(round)) appartiene a G1
      var HC = CryptoUtils.H1(round);
      Console.WriteLine($"HC: {HC.GetStr(16)}");

      // Carica P (chiave pubblica della rete drand di LOE)
      var bytes_pkloe = CryptoUtils.FromHexStr(PKLOEstring);
      var PKLOE = new G2();
      PKLOE.Deserialize(bytes_pkloe);
      if (!PKLOE.IsValid()) throw new Exception("PKLOEstring not valid!");
      Console.WriteLine($"PKLOE: {PKLOE.GetStr(16)}");

      //Calcola Gid=e(sha256(round), P)
      var Gid = new GT();
      Gid.Pairing(HC, PKLOE);
      Console.WriteLine($"Gid: {Gid.GetStr(16)}");
      if (!Gid.IsValid()) throw new Exception("Gid is not valid!");

      //sceglie il valore casuale di sigma
      var messaggio = "Ciao Ali";
      var sigma = CryptoUtils.GetSecureRandomNumber(messaggio.Length * 8).ConvertToBigIntergerBC();
      var bytes_sigma = sigma.ToByteArray();

      //Calcola r=H3(sigma,M)
      var M = System.Text.Encoding.UTF8.GetBytes(messaggio); //  il messaggio deve essere max 256 bit (lunghezza massima dell'hash SHA256)
      var h3 = H3(bytes_sigma, M);
      var bytes_h3 = h3.ToByteArray();

      //Calcola C={U,V,W}

      //Calcola U=rG2
      //mclBn_setETHserialization(1);      
      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);
      if (!g2.IsValid()) throw new Exception("g1 not valid!");
      //mclBn_setETHserialization(0);
      var U = new G2();
      var r = new Fr();
      r.Deserialize(bytes_h3);
      if (!r.IsValid()) throw new Exception("r is not valid!");
      U.Mul(g2, r);
      if (!U.IsValid()) throw new Exception("U is not valid!");

      //Calcola V=sigma XOR H2(Gid^r)
      var Gid_pow_r = new GT();
      Gid_pow_r.Pow(Gid, r);
      if (!Gid_pow_r.IsValid()) throw new Exception("Gid_pow_r is not valid!");
      var h2 = GetSHA256(Gid_pow_r.Serialize());
      var bi_h2 = new BigInteger(h2);
      var V = sigma.Xor(bi_h2);

      //Calcola W=M XOR H4(sigma)
      var bi_M = new BigInteger(M);
      var h4 = GetSHA256(bytes_sigma);
      var bi_h4 = new BigInteger(h4);
      var W = bi_M.Xor(bi_h4);
      return (U, V, W);
    }
    public static string Decrypt_BLSonG1((G2 U, BigInteger V, BigInteger W) cipherText, string sigLOEstring)
    {
      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");

      // Calcola sigma' = V xor H2(e(sigLOE,U))      
      var SigLOE = new G1();
      //mclBn_setETHserialization(1);
      var bytes_SKLOE = CryptoUtils.FromHexStr(sigLOEstring);
      SigLOE.Deserialize(bytes_SKLOE);
      if (!SigLOE.IsValid()) throw new Exception("SigLOEstring not valid!");
      //mclBn_setETHserialization(0);
      var e = new GT();
      e.Pairing(SigLOE, cipherText.U);
      var H2 = GetSHA256(e.Serialize());
      var bi_H2 = new BigInteger(H2);
      var sigma = cipherText.V.Xor(bi_H2);
      var bytes_sigma = sigma.ToByteArray();

      //Calcola M' = W XOR H4(sigma')
      var H4 = GetSHA256(bytes_sigma);
      var bi_H4 = new BigInteger(H4);
      var M = cipherText.W.Xor(bi_H4);
      var bytes_M = M.ToByteArray();

      //r' = H3(sigma',M')
      var bi_r = H3(bytes_sigma, bytes_M);
      var bytes_r = bi_r.ToByteArray();
      var r = new Fr();
      r.Deserialize(bytes_r);
      if (!r.IsValid()) throw new Exception("r not valid!");

      // check U == r'G2
      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      //mclBn_setETHserialization(1);
      var g2 = new G2();
      g2.SetStr(g2Str, 16);
      if (!g2.IsValid()) throw new Exception("g1 not valid!");
      //mclBn_setETHserialization(0);
      var U = new G2();
      U.Mul(g2, r);
      if (U.Equals(cipherText.U)) return System.Text.Encoding.UTF8.GetString(bytes_M);
      else return "ERROR!";
    }
  }
}

