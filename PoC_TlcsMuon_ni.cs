
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Collections;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static mcl.MCL;

namespace TimeCryptor
{
  public static class PoC_TlcsMuon_ni
  {
    static LeagueOfEntropy _LOE = new LeagueOfEntropy();
    static Blockchain _blockChain = new Blockchain();
    static GlobalParams _globalParams = new GlobalParams();
    static Contributor[] _contributors = null;

    //Crea una coppia di chiavi per la curva ellittica scelta ed effettua una cifratura/decifratura di un messaggio con ECIES
    public static void TestPoC()
    {
      // LOE Round di riferimento
      //"round": 9792114,      
      //"randomness": "64ec4b3b2c4a16960e87e12a4c4df192d18d88a200e9e8478bb8a01e9f1d6c68", /* hash SHA256 del campo signature */
      //"signature":"8440a7152497a74e806737e5614a957998f149d80fe342cb56d33339de045b9cf573216bd8916f8741a86f8bac20d1cb"
      
      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE
      _globalParams.ecCurveName = CryptoUtils.ECname.secp256k1.ToString();
      //var ecParams = GetEcDomainParametersDirect(ecCurveName);
      _globalParams.ecParams = CryptoUtils.GetEcDomainParametersByEcName(_globalParams.ecCurveName);
      _globalParams.k = 3; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;

      Console.WriteLine("\n=== CONFIGURAZIONI GENERALI ===");
      Console.WriteLine($"numeroContributori: {_globalParams.numeroContributori}");
      Console.WriteLine($"parametro di sicurezza k: {_globalParams.k}");
      Console.WriteLine($"Curva ellittica scelta: {_globalParams.ecCurveName}");

      //IMPOSTO LA DATA FUTURA, RECUPERO LA DATA FUTURA
      //var round = 10750255;
      var futureDateTime = DateTime.Now.AddSeconds(5);
      var round = LeagueOfEntropy.GetRound(futureDateTime);
      Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");
      _LOE.CreateKeyPair(round);
      _globalParams.PKLOE = (G2)_LOE.pk;

      //L'INSIEME DI PARTI GENERANO I PARAMETRI PUBBLICI E LI PUBBLICANO SULLA BLOCKCHAIN       
      _contributors = new Contributor[_globalParams.numeroContributori];
      Console.WriteLine("\n=== GENERAZIONE PARAMETRI PUBBLICI ===");
      for (int i = 1; i <= _globalParams.numeroContributori; i++)
      {
        var P = new Contributor($"P{i}", _globalParams.ecParams, _globalParams.k, round);
        P.SetPublicParams(round, _globalParams.PKLOE, _globalParams);

        if (i == 2) P.PublishToBlockchain(_blockChain, true); //simula un contributo non onesto
        else P.PublishToBlockchain(_blockChain);
        _contributors[i - 1] = P;
      }

      //PROCEDURA DI VERIFICA DELLE PROVE 
      Console.WriteLine("\n=== VERIFICA DELLE PROVE ===");
      var verifiedContributorNameList = SmartContract.Verify(round, _blockChain, _globalParams);

      //PROCEDURA DI AGGREGAZIONE
      Console.WriteLine("\n=== AGGREGAZIONE - CALCOLO MPK_R ===");
      var MPK_R = SmartContract.Aggregate(round, _blockChain, verifiedContributorNameList);

      //ENCRYPT            
      Console.WriteLine($"\n=== CIFRATURA CON LA CHIAVE MPK_R ===");
      //CARICA LA CHIAVE PUBBLICA DEL DESTINATARIO
      var publicKeyParameters = new ECPublicKeyParameters(MPK_R, _globalParams.ecParams);

      //GENERA LA COPPIA DI CHIAVI DEL MITTENTE
      var keyPairSender = ECIES.GenerateECIESKeyPair(_globalParams.ecParams);
      var message = "Hello TLE!";
      var cipherText = ECIES.Encrypt(message, keyPairSender.Private, publicKeyParameters);
      var cipherTextString = Convert.ToBase64String(cipherText);
      Console.WriteLine($"Testo originale: {message}");
      Console.WriteLine($"Testo cifrato: {cipherTextString}");
      Console.WriteLine($"Blocco temporale fino a : {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")}");

      Console.WriteLine("\n=== RECUPERO LA FIRMA LOE ===");
      var sigmaLOE = _LOE.GetSigma(round);
      //if (sigmaLOE == null)  { Console.WriteLine($"SIGMA LOE non ancora disponibile! Attendere fino a {LeagueOfEntropy.GetDateFromRound(round).ToString("dd/MM/yyyy HH:mm:ss")}"); }
      while (sigmaLOE == null)
      { 
        Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
        Thread.Sleep(1000);
        sigmaLOE = _LOE.GetSigma(round);
      }
      Console.WriteLine("...FIRMA LOE DISPONIBILE!");
      Console.WriteLine($"{((G1)sigmaLOE).GetStr(16)}");
      Console.WriteLine($"sigmaLOE: {((G1)sigmaLOE).ToCompressedPoint()}");
      

      //PROCEDURA DI INVERSIONE
      Console.WriteLine("\n=== INVERSIONE - CALCOLO DI sk_R ===");
      Console.WriteLine("\n=== Calcolo della sk_R - procedura di aggregazione delle chiavi segrete parziali sk della parti ===");
      var sk_R = SmartContract.Invert(round, (G1)sigmaLOE, _blockChain, _globalParams);
      Console.WriteLine($"sk_R: {sk_R.ToString(16)}");
      CryptoUtils.CheckValidKeyPair(MPK_R, sk_R, _globalParams.ecParams);

      //DECRYPT
      Console.WriteLine($"\n=== DECIFRATURA CON LA CHIAVE sk_R ===");
      //chiave privata del destinatario
      var privateKeyParameters = new ECPrivateKeyParameters(sk_R, _globalParams.ecParams);

      //Mostra la chiave privata del destinatario serializzata
      //var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParameters);
      //byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();
      //string serializedPrivate = Convert.ToBase64String(serializedPrivateBytes);
      //Console.WriteLine($"sk: {serializedPrivate}");

      var plainText = ECIES.Decrypt(cipherText, keyPairSender.Public, privateKeyParameters);
      Console.WriteLine($"Testo decifrato: {plainText}");
    }

    public class LeagueOfEntropy
    {
      private G2? _pk;
      public G2? pk
      {
        get
        {
          if (_pk == null) throw new Exception("Chiavi LOE non ancora create!");
          else return _pk;
        }
        set { _pk = value; }
      }
      private Fr sk { get; set; }
      private G1 sigma { get; set; }

      public static bool checkFirma(int round, G1 sigma, G2 pk)
      {
        Init(BLS12_381);
        ETHmode();

        var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
        var g2 = new G2(); //Zp
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

      /// <summary>
      /// Simula la geneazione della chiave pubblica (pk) di LOE e della firma (sigma)
      /// Genera un coppia di chiavi (sk,pk) e genera la firma BLS sul messaggio=round usando la chiave segreta sk sulla curva BLS12-381
      /// </summary>
      /// <param name="round">il numero di round</param>
      /// <returns>(Fr sk, G2 pk, G1 sigma)</returns>
      public void CreateKeyPair(int round)
      {
        //Test di una firma BLS
        Init(BLS12_381);
        ETHmode();

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
        Console.WriteLine($"\n=== PARAMETRI LOE ===");
        Console.WriteLine($"Round: {round}");
        Console.WriteLine($"sk LOE: {sk.GetStr(16).ToLower()}");  //simula chiave segreta LOE
        Console.WriteLine($"pk LOE: {pk.ToCompressedPoint()}"); //simula PKLOE
        Console.WriteLine($"Firma BLS LOE: {sigma.ToCompressedPoint()}"); //simula FIRMA LOE
                                                                 //Console.WriteLine($"e1: {e1.GetStr(16).Print()}");
                                                                 //Console.WriteLine($"e2: {e2.GetStr(16).Print()}");
        Console.WriteLine($"verifica firma: {verificaFirma.ToString()} ");
        Console.WriteLine($"=== PARAMETRI LOE ===");

        this.sk = sk;
        this.pk = pk;
        this.sigma = sigma;
      }

      /// <summary>
      /// Calcola il numero di round associato a una data futura specifica passata come parametro
      /// si assume di utilizzare la rete dranad Quicknet (con genesystime = 1692803367 e period = 3)
      /// Dati della rete recuperabili tramite questo link https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
      /// </summary>
      /// <param name="futureDateTime">Data futura</param>
      /// <returns></returns>
      public static int GetRound(DateTime futureDateTime)
      {
        const int drand_genesis_time = 1692803367; //drand quicknet genesis time
        const int period = 3;
        decimal futureDateTime_unix = ((DateTimeOffset)futureDateTime).ToUnixTimeSeconds();
        decimal round = ((futureDateTime_unix - drand_genesis_time) / period); //Valore intero minimo maggiore o uguale a round (arrotondamento divisione per eccesso es. 1.3 => 2)
        var ret = Math.Ceiling(round);
        return (int)ret;
      }

      public static DateTime GetDateFromRound(int round)
      {
        const int drand_genesis_time = 1692803367; //drand quicknet genesis time
        const int period = 3;
        var d = (round * period) + drand_genesis_time;
        var retDate = DateTimeOffset.FromUnixTimeSeconds(d);
        return retDate.DateTime.ToLocalTime();
      }

      public G1? GetSigma(int round)
      {
        if (DateTime.Now >= GetDateFromRound(round))
          return this.sigma;
        else
          return null;
      }
    }
    public class GlobalParams
    {
      public GlobalParams()
      {
        Init(BLS12_381);
        ETHmode();
        var g2Str16 = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
        var gen_g2 = new G2();
        gen_g2.SetStr(g2Str16, 16);
        g2 = gen_g2;
      }
      public string ecCurveName { get; set; }
      public ECDomainParameters ecParams { get; set; }
      public int k { get; set; } //parametro di sicurezza per errore di solidità
      public int numeroContributori { get; set; }
      public G2 g2 { get; set; }
      public G2 PKLOE { get; set; }
    }
    public class Contributor
    {
      private int k { get; set; }
      private int Round { get; set; }
      public string Name { get; set; }
      public ECDomainParameters ecParams { get; set; }
      
      private BigInteger sk { get; set; }
      public BigInteger t { get; set; } //da recuperare per la verifica della prova da parte del verifier
      
      public Org.BouncyCastle.Math.EC.ECPoint PK { get; set; }
      public G2 T { get; set; } //Hex string
      public BigInteger y { get; set; }

      public bool[] b { get; set; } // contenente l'array dei bit di casaulità per la verifica delle prove
      public Proof_Item[] proof { get; set; }
      public Contributor(string contributorName, ECDomainParameters ecDomainParameters, int k, int round)
      {
        this.ecParams = ecDomainParameters;
        this.k = k;
        this.Round = round;
        this.Name = contributorName;
      }
      public PK_T_y_ItemExtended getPK_T_y(int round, G2 PKLOE, BigInteger sk)
      {
        Init(BLS12_381);
        ETHmode();

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
        var bi_round = new BigInteger(round.ToString(), 10);
        var bytes_Round = bi_round.ToByteArray();
        var HC = new G1();
        HC.HashAndMapTo(bytes_Round); //H1(C)

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

      public void PublishToBlockchain(Blockchain bc, bool simulaContributoriNonOnesto = false)
      {
        var item = new Blockchain_Item();
        item.round = this.Round;
        item.pp = new PK_T_y_Item() { PK = this.PK, T = this.T, y = this.y };
        item.proof = new Proof_ItemOnBlockchain[this.k];
        for (int i = 0; i < this.k; i++)
        {
          item.proof[i] = new Proof_ItemOnBlockchain();
          item.proof[i].left = new PK_T_y_ItemExtended() { PK = this.proof[i].left.PK, T = this.proof[i].left.T, y = this.proof[i].left.y };
          item.proof[i].right = new PK_T_y_ItemExtended() { PK = this.proof[i].right.PK, T = this.proof[i].right.T, y = this.proof[i].right.y };

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

        if (simulaContributoriNonOnesto)
        {
          Console.WriteLine($"\n=== Creazione chiave pubblica malevola della Parte {this.Name} ===");
          var skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
          var sk_X = skField.ToBigInteger();
          var PK_X = ecParams.G.Multiply(sk_X);
          if (!PK_X.IsValid()) throw new Exception("PK_X not valid!");
          item.pp.PK = PK_X;
        }

        item.contributorName = this.Name;
        bc.Put(item);
      }

      public void SetPublicParams(int round, G2 PKLOE, GlobalParams globalParams)
      {
        Console.WriteLine($"\n=== Creazione parametri pubblici della Parte {this.Name} ===");
        //var array_b_string = "";
        
        var skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
        var sk = skField.ToBigInteger();
        this.sk = sk;
        var PK = ecParams.G.Multiply(sk);
        if (!PK.IsValid()) throw new Exception("PK not valid!");
        
        //CREA la lista delle tuple (〖PK〗_(j,b),T_(j,b),y_(j,b) )_(j∈[k],b∈{1,2} )
        var pp = getPK_T_y(round, PKLOE, sk);
        //imposto i valori pubblici      
        this.PK = pp.PK;
        this.T = pp.T;
        this.y = pp.y;
        Console.WriteLine($"PK: {this.PK.ToCompressedPoint()}");
        Console.WriteLine($"T: {this.T.ToCompressedPoint()}");
        Console.WriteLine($"y: {this.y.ToString(16)}");
                
        //array_b_string += this.PK.Normalize().ToCompressedPoint();

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
          this.proof[j].left = getPK_T_y(round, PKLOE, array_sk[0]);
          this.proof[j].right = getPK_T_y(round, PKLOE, array_sk[1]);

          //array_b_string += this.proof[j].left.PK.Normalize().ToCompressedPoint() + this.proof[j].left.T.GetStr(16) + this.proof[j].left.y;
          //array_b_string += this.proof[j].right.PK.Normalize().ToCompressedPoint() + this.proof[j].right.T.GetStr(16) + this.proof[j].right.y;
        }

        //Crea l'array b come hash della stringa [〖PK,(〖PK〗_(j,b),T_(j,b),y_(j,b) )〗_(j∈[k],b∈{1,2} )]. 
        this.b = Utils.GetRandomArrayForProof(this, globalParams.k);
      }
      public BigInteger GetPrivateKey(G1 sigmaLOE)
      {
        Init(BLS12_381);
        ETHmode();

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
      public bool checkSK(BigInteger skToCheck)
      {
        return this.sk.Equals(skToCheck);
      }
    }
    public static class Utils
    {
      public static BigInteger getSk(PK_T_y_ItemExtended tupleToBeVerify, G1 sigmaLOE)
      {
        var Zjb = new GT();
        Zjb.Pairing(sigmaLOE, tupleToBeVerify.T); //Zi=e(sigmaR,Tjb)
        if (!Zjb.IsValid()) throw new Exception("Zi not valid!");
        
        var Zjbbytes = Zjb.Serialize();
        var hashZjb = CryptoUtils.GetSHA256(Zjbbytes); //H(Zi)
                                                       
        var ZjbBigInt = new BigInteger(hashZjb);
        var skjb = tupleToBeVerify.y.Xor(ZjbBigInt);

        return skjb;
      }
      public static bool[] GetRandomArrayForProof(Contributor contributor, int k)
      {
        var array_b_string = "";
        array_b_string += contributor.PK.Normalize().ToCompressedPoint().ToLower();
        for (int j = 0; j < k; j++)
        {
          array_b_string += contributor.proof[j].left.PK.Normalize().ToCompressedPoint().ToLower() + contributor.proof[j].left.T.GetStr(16) + contributor.proof[j].left.y;
          array_b_string += contributor.proof[j].right.PK.Normalize().ToCompressedPoint().ToLower() + contributor.proof[j].right.T.GetStr(16) + contributor.proof[j].right.y;
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

      public static bool[] GetRandomArrayForProof(Blockchain_Item bcItem, int k)
      {
        var array_b_string = "";
        array_b_string += bcItem.pp.PK.Normalize().ToCompressedPoint().ToLower();
        for (int j = 0; j < k; j++)
        {
          array_b_string += bcItem.proof[j].left.PK.Normalize().ToCompressedPoint().ToLower() + bcItem.proof[j].left.T.GetStr(16) + bcItem.proof[j].left.y;
          array_b_string += bcItem.proof[j].right.PK.Normalize().ToCompressedPoint().ToLower() + bcItem.proof[j].right.T.GetStr(16) + bcItem.proof[j].right.y;
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
    public static class SmartContract
    {
      /// <summary>
      /// verifica che le prove che accompagnano i parametri pubblici inviati dalle parti siano valide
      /// </summary>
      /// <param name="round"></param>
      /// <param name="bc"></param>
      public static List<string> Verify(int round, Blockchain bc, GlobalParams globalParams)
      {
        Init(BLS12_381);
        ETHmode();

        var retVerifiedContributors = new List<string>(); //lista dei contributiori validi, per cui la verifica delle prove h adato esito positivo
        
        //Recupera i dati dei parametri pubblici pubblicati dai contributori sulla blockchain 
        var bcRoundItemList = bc.PopByRound(round);

        foreach (var bcRoundItem in bcRoundItemList)
        { 
          var b = Utils.GetRandomArrayForProof(bcRoundItem, globalParams.k);

          var check = false;
          for (int j = 0; j < globalParams.k; j++)
          {
            //controllo (1) - VERIFICA DELLA CHIAVE PK DELLE PROVE
            var PKj_sum = bcRoundItem.proof[j].left.PK.Add(bcRoundItem.proof[j].right.PK);
            check = bcRoundItem.pp.PK.Equals(PKj_sum);
            if (!check) break;
            
            PK_T_y_ItemExtended proofToBeVerify = null;
            switch (b[j])
            {
              case false:
                proofToBeVerify = bcRoundItem.proof[j].left;                
                break;
              case true:
                proofToBeVerify = bcRoundItem.proof[j].right;                
                break;
              default:
                throw new Exception("b array contain invalid values!");
            }

            //controllo (2) - VERIFICA dei T attraverso in base al vettore di bit di casualita scelto dal verifier
            var T_temp = new G2();
            T_temp.Mul(globalParams.g2, proofToBeVerify.t);   //Ti=g2^ti
            check = proofToBeVerify.T.Equals(T_temp);
            if (!check) break;

            //controllo (3)
            //HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))      
            var bi_round = new BigInteger(round.ToString(), 10);
            var bytes_Round = bi_round.ToByteArray();
            var HC = new G1();
            HC.HashAndMapTo(bytes_Round); //H1(C)

            var Z_temp = new GT();
            var e = new GT();
            e.Pairing(HC, globalParams.PKLOE);   // e(H1(C),PKL)
            Z_temp.Pow(e, proofToBeVerify.t);            // Zi = e(H1(C),PKL)^ti
            if (!Z_temp.IsValid()) throw new Exception("Z_temp not valid!");

            byte[] Zbytes = Z_temp.Serialize();
            byte[] HashZ = CryptoUtils.GetSHA256(Zbytes); // H(Zi)                                                 

            var ZBigInt = new BigInteger(HashZ);
            var sk = ZBigInt.Xor(proofToBeVerify.y);     //H(Zi) XOR y

            var PK_temp = globalParams.ecParams.G.Multiply(sk);
            check = proofToBeVerify.PK.Equals(PK_temp);             //g^(〖sk〗_(j,b_j)^' )==〖PK〗_(j,b_j )
            if (!check) break;
          }

          //Se tutti i controlli (1)(2)(3) passano il contributore viene messo nella lista dei contributori validi
          if (check) retVerifiedContributors.Add(bcRoundItem.contributorName);
          Console.WriteLine($"Parte {bcRoundItem.contributorName} - Prova NIZK {((check) ? "valida" : "NON valida!")}");
        }
        Console.WriteLine($"Parti valide {retVerifiedContributors.Count}/{globalParams.numeroContributori}");
        return retVerifiedContributors;
      }

      /// <summary>
      /// Esegue la procedura di aggregazione delle chiavi pubbliche parziali per generare la chiave pubblica master
      /// </summary>
      /// <param name="round"></param>
      /// <param name="bc"></param>
      /// <param name="verifiedContributorNameList">Le parti per cui la prova NIZK è valida</param>
      /// <returns></returns>
      public static Org.BouncyCastle.Math.EC.ECPoint Aggregate(int round, Blockchain bc, List<string> verifiedContributorNameList)
      {
        Console.WriteLine("\n=== CALCOLO DI MPK_R - AGGREGAZIONE DELLE CHIAVI PARZIALI DELLE PARTI ===");
        // recupero solo gli item dei contributori onesti (la cui prova è corretta)
        var bcRoundItemList = bc.Items.Where(s => s.round == round && verifiedContributorNameList.Contains(s.contributorName)).ToList();
        var i = 1;
        var MPK_R = bcRoundItemList[0].pp.PK;
        for (i = 1; i <= bcRoundItemList.Count - 1; i++)
        {
          MPK_R = MPK_R.Add(bcRoundItemList[i].pp.PK);
        }
        Console.WriteLine($"MPK_R: {MPK_R.ToCompressedPoint().ToLower()}");
        var checkVal = MPK_R.IsValid();
        Console.WriteLine($"MPK_R IsValid: {checkVal}");
        return MPK_R;
      }

      /// <summary>
      /// Esegue la procedura di inversione della chiave pubblica 
      /// </summary>
      /// <param name="round"></param>
      /// <param name="sigmaLOE"></param>
      /// <param name="bc"></param>
      /// <param name="ecParams"></param>
      /// <returns></returns>
      /// <exception cref="Exception"></exception>
      public static BigInteger Invert(int round, G1 sigmaLOE, Blockchain bc, GlobalParams globalParams)
      {
        Init(BLS12_381);
        ETHmode();

        Console.Write("\n=== VERIFICA FIRMA LOE ===");
        var checkFirmaLOE = LeagueOfEntropy.checkFirma(round, sigmaLOE, globalParams.PKLOE);
        if (!checkFirmaLOE) throw new Exception("Firma LOE non valida!");
        else Console.Write("\nFirma LOE valida!\n\n");

        //Recupero i parametri dalla blockChain
        var bcRoundItemList = bc.Items.Where(s => s.round == round).ToList();
        var array_sk = new BigInteger[bcRoundItemList.Count];
        var i = 0;
        foreach (var bcRoundItem in bcRoundItemList)
        {
          Console.WriteLine($"\n=== RICOSTRUZIONE CHIAVE PARAZIALE PARTE {bcRoundItem.contributorName} ===");
          var check = false;
          for (int j = 0; j < globalParams.k; j++)
          {
            var sk1 = Utils.getSk(bcRoundItem.proof[j].left,sigmaLOE);
            var PK1_temp = globalParams.ecParams.G.Multiply(sk1);
            var sk2 = Utils.getSk(bcRoundItem.proof[j].right, sigmaLOE);
            var PK2_temp = globalParams.ecParams.G.Multiply(sk2);
            var checkPK = PK1_temp.Equals(bcRoundItem.proof[j].left.PK) && PK2_temp.Equals(bcRoundItem.proof[j].right.PK);

            var PKj_sum = bcRoundItem.proof[j].left.PK.Add(bcRoundItem.proof[j].right.PK);
            var checkPKsum = bcRoundItem.pp.PK.Equals(PKj_sum);

            var skj = sk1.Add(sk2).Mod(globalParams.ecParams.N);
            CryptoUtils.CheckValidKeyPair(bcRoundItem.pp.PK, skj, globalParams.ecParams); //verifica la validita della coppia di chiavi generate per il round
            if (checkPK && checkPKsum)
            { 
              Console.WriteLine($"{bcRoundItem.contributorName} sk (tlcs): {skj.ToString(16).ToLower()} (chiave segreta ricostruita)");              
              array_sk[i++] = skj;
              check = true;
              break;
            } 
          }
          if (!(check)) Console.WriteLine($"{bcRoundItem.contributorName} sk (tlcs): (chiave segreta NON valida!)");
        }

        Console.WriteLine("\n=== AGGREGA LE CHIAVI PRIVATE PARZIALI DELLE PARTI ===");
        //aggrega le chiavi private parziali ricostruite di tutte le parti (i contributori) per ricostruire la chiave segreta sk_r
        var sk_r = array_sk[0];
        for (i = 1; i <= array_sk.Length - 1; i++)
        {
          if (array_sk[i]!=null) sk_r = sk_r.Add(array_sk[i]).Mod(globalParams.ecParams.N);
        }
        return sk_r;
      }
    }
    public class PK_T_y_Item
    {
      public Org.BouncyCastle.Math.EC.ECPoint PK { get; set; }
      public G2 T { get; set; }
      public BigInteger y { get; set; }
    }
    public class PK_T_y_ItemExtended : PK_T_y_Item
    {
      public Fr t { get; set; } //da usare solo nelle proof e deve essere cancellato dalal tupla pubblicata sulla blockchain
    }
    public class Proof_Item
    {
      public PK_T_y_ItemExtended left { get; set; } //0
      public PK_T_y_ItemExtended right { get; set; } //1
    }
    public class Proof_ItemOnBlockchain
    {
      public PK_T_y_ItemExtended left { get; set; } //0
      public PK_T_y_ItemExtended right { get; set; } //1
    }
    public class Blockchain
    {
      public List<Blockchain_Item> Items = null;
      public Blockchain()
      {
        Items = new List<Blockchain_Item>();
      }
      public void Put(Blockchain_Item item)
      {
        Items.Add(item);
      }
      public Blockchain_Item PopByContributorName(string cName)
      {
        return Items.Single(s => s.contributorName == cName);
      }
      public List<Blockchain_Item> PopByRound(int round)
      {
        return Items.Where(s => s.round == round).ToList();
      }
    }
    public class Blockchain_Item
    {
      public int round { get; set; }
      public string contributorName { get; set; }
      public PK_T_y_Item pp { get; set; }
      public Proof_ItemOnBlockchain[] proof { get; set; }
    }
  }
}