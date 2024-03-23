﻿
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static mcl.MCL;

namespace TimeCryptor
{
  public static class PoC_TlcsMuon_i
  {
    static LeagueOfEntropy _LOE;
    static Blockchain _blockChain;
    static GlobalParams _globalParams;
    static Contributor[] _contributors;

    //Crea una coppia di chiavi per la curva ellittica scelta ed effettua una cifratura/decifratura di un messaggio con ECIES
    public static void Run_PoC()
    {
      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"); //DST da impostare in base alla chain drand da utilizzare 
      //G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain (quelle non conformi a RFC drand viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2

      _LOE = new LeagueOfEntropy(LeagueOfEntropy.KeyModeEnum.FromWeb);
      _blockChain = new Blockchain();
      _globalParams = new GlobalParams();
      _contributors = null;

      // LOE Round di riferimento
      //"round": 9792114,      
      //"randomness": "64ec4b3b2c4a16960e87e12a4c4df192d18d88a200e9e8478bb8a01e9f1d6c68", /* hash SHA256 del campo signature */
      //"signature":"8440a7152497a74e806737e5614a957998f149d80fe342cb56d33339de045b9cf573216bd8916f8741a86f8bac20d1cb"

      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE
      _globalParams.ecCurveName = CryptoUtils.ECname.secp256k1.ToString();
      //var ecParams = GetEcDomainParametersDirect(ecCurveName);
      _globalParams.ecParams = CryptoUtils.GetEcDomainParametersByEcName(_globalParams.ecCurveName);
      _globalParams.k = 2; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;

      Console.WriteLine("\n=== CONFIGURAZIONI GENERALI ===");
      Console.WriteLine($"numeroContributori: {_globalParams.numeroContributori}");
      Console.WriteLine($"parametro di sicurezza k: {_globalParams.k}");
      Console.WriteLine($"Curva ellittica scelta: {_globalParams.ecCurveName}");

      //IMPOSTO LA DATA FUTURA e RECUPERO IL NUMERO DI ROUND      
      var futureDateTime = DateTime.Now.AddSeconds(10); //blocco temporale 10 secondi
      ulong round = LeagueOfEntropy.GetRound(futureDateTime);
      Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");
      _LOE.Round = round;
      _globalParams.PKLOE = (G2)_LOE.pk;

      //L'INSIEME DI PARTI GENERANO I PARAMETRI PUBBLICI E LI PUBBLICANO SULLA BLOCKCHAIN       
      _contributors = new Contributor[_globalParams.numeroContributori];
      Console.WriteLine("\n=== GENERAZIONE PARAMETRI PUBBLICI ===");
      for (int i = 1; i <= _globalParams.numeroContributori; i++)
      {
        var P = new Contributor($"P{i}", _globalParams.ecParams, _globalParams.k, round);
        P.SetPublicParams(round, _globalParams.PKLOE);

        if (i == 2) P.PublishToBlockchain(true); //simula un contributo non onesto
        else P.PublishToBlockchain();
        _contributors[i - 1] = P;
      }

      //PROCEDURA DI VERIFICA DELLE PROVE 
      Console.WriteLine("\n=== VERIFICA DELLE PROVE ===");
      var verifiedContributorNameList = SmartContract.Verify(round);
      Console.WriteLine($"Parti valide {verifiedContributorNameList.Count}/{_globalParams.numeroContributori}");

      //PROCEDURA DI AGGREGAZIONE
      Console.WriteLine("\n=== AGGREGAZIONE - CALCOLO MPK_R ===");
      var MPK_R = SmartContract.Aggregate(round, verifiedContributorNameList);

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
      
      G1? sigmaLOE = null;
      //if (sigmaLOE == null)  { Console.WriteLine($"SIGMA LOE non ancora disponibile! Attendere fino a {LeagueOfEntropy.GetDateFromRound(round).ToString("dd/MM/yyyy HH:mm:ss")}"); }
      while (sigmaLOE == null)
      {
        sigmaLOE = _LOE.sigma; //richiede la firma 
        Console.WriteLine("...attendo...");
        Thread.Sleep(2000);

        /*
        if (DateTime.Now >= LeagueOfEntropy.GetDateFromRound(round))
        {
          sigmaLOE = _LOE.sigma; //richiede la firma 
        }
        else
        {
          Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
          Thread.Sleep(1000);
        } 
        */
      }
      Console.WriteLine("...FIRMA LOE DISPONIBILE!");
      Console.WriteLine($"{((G1)sigmaLOE).GetStr(16)}");

      //PROCEDURA DI INVERSIONE
      Console.WriteLine("\n=== INVERSIONE - CALCOLO DI sk_R ===");
      Console.WriteLine("\n=== Calcolo della sk_R - procedura di aggregazione delle chiavi segrete parziali sk della parti ===");
      var sk_R = SmartContract.Invert(round, (G1)sigmaLOE, _globalParams.ecParams, verifiedContributorNameList);
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

    public static Fr Get_t_fromContributor(ulong round, string contributorName, int proofId, int randomBit)
    {
      Fr t;
      var contributor = _contributors.Single(s => s.Name == contributorName);
      switch (randomBit)
      {
        case 0:
          t = contributor.proof[proofId].left.t;
          break;
        case 1:
          t = contributor.proof[proofId].right.t;
          break;
        default:
          throw new Exception("rndBitArray array contain invalid values!");
      }
      return t;
    }
    public class GlobalParams
    {
      public GlobalParams()
      {
        //Init(BLS12_381);
        //ETHmode();
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
      private ulong round { get; set; }
      public string Name { get; set; }
      public ECDomainParameters ecParams { get; set; }

      private BigInteger sk { get; set; }
      //public Fr t { get; set; }
      private BigInteger Z { get; set; }

      public Org.BouncyCastle.Math.EC.ECPoint PK { get; set; }
      public G2 T { get; set; } //Hex string
      public BigInteger y { get; set; }

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

      public void PublishToBlockchain(bool simulaContributoriNonOnesto = false)
      {
        var item = new Blockchain_Item();
        item.round = this.round;
        item.pp = new PK_T_y_Item() { PK = this.PK, T = this.T, y = this.y };
        item.proof = new Proof_ItemOnBlockchain[this.k];
        for (int i = 0; i < this.k; i++)
        {
          item.proof[i] = new Proof_ItemOnBlockchain();
          item.proof[i].left = new PK_T_y_Item() { PK = this.proof[i].left.PK, T = this.proof[i].left.T, y = this.proof[i].left.y };
          item.proof[i].right = new PK_T_y_Item() { PK = this.proof[i].right.PK, T = this.proof[i].right.T, y = this.proof[i].right.y };
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
        _blockChain.Put(item);
      }

      public void SetPublicParams(ulong round, G2 PKLOE)
      {
        Console.WriteLine($"\n=== Creazione parametri pubblici della Parte {this.Name} ===");
        var skField = ecParams.Curve.RandomFieldElement(new SecureRandom());
        var sk = skField.ToBigInteger();
        this.sk = sk;
        var PK = ecParams.G.Multiply(sk);
        if (!PK.IsValid()) throw new Exception("PK not valid!");

        var pp = GetPK_T_y(round, PKLOE, sk);
        //imposto i valori pubblici      
        this.PK = pp.PK;
        this.T = pp.T;
        this.y = pp.y;
        Console.WriteLine($"PK: {this.PK}");
        Console.WriteLine($"T: {this.T.GetStr(16)}");
        Console.WriteLine($"y: {this.y.ToString(16)}");

        //CREA la lista delle tuple (〖PK〗_(j,b),T_(j,b),y_(j,b) )_(j∈[k],b∈{1,2} )
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
          proof[j] = new Proof_Item();
          proof[j].left = GetPK_T_y(round, PKLOE, array_sk[0]);
          proof[j].right = GetPK_T_y(round, PKLOE, array_sk[1]);
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

    }
    public static class SmartContract
    {
      public static int[] ChooseRandomBitArray(int k)
      {
        //Il verifier sceglie un array di k bit casuali (usando gli interi 0 e 1)
        var b = new int[k];
        Random r = new Random();
        while (b.Any(item => item == 1) == false)
        {
          for (int i = 0; i < b.Length; i++)
          {
            b[i] = r.Next(0, 2);
          }
        }
        return b;
      }

      public static List<string> Verify(ulong round)
      {
        var verifiedContributorNameList = new List<string>();
        var bcRoundItemList = _blockChain.PopByRound(round);
        foreach (var bcRoundItem in bcRoundItemList)
        {
          var rndBitArray = SmartContract.ChooseRandomBitArray(_globalParams.k);
          var contributor = _contributors.Single(s => s.Name == bcRoundItem.contributorName);

          var check = false;
          for (int j = 0; j < _globalParams.k; j++)
          {
            //Simula l'interazione tra verifier e prover - il verifier richiede al prover il parametro privato t della prova che vuole verificare (in base al valore casuale da lui scelto nell'array di bit rndBitArray)
            var tFromContributor = Get_t_fromContributor(round, bcRoundItem.contributorName, j, rndBitArray[j]);
            
            check = SmartContract.VerifyProof(round, j, rndBitArray, bcRoundItem, tFromContributor, _globalParams);
            if (!check) break;
          }
          //Se tutti i controlli (1)(2)(3) passano il contributore viene messo nella lista dei contributori validi
          if (check) verifiedContributorNameList.Add(bcRoundItem.contributorName);
          Console.WriteLine($"Parte {bcRoundItem.contributorName} - Prova NIZK {((check) ? "valida" : "NON valida!")}");
        }

        return verifiedContributorNameList;
      }

      /// <summary>
      /// verifica che le prove che accompagnano i parametri pubblici inviati dalle parti siano valide
      /// </summary>
      /// <param name="round"></param>
      /// <param name="bc"></param>
      public static bool VerifyProof(ulong round, int j, int[] rndBitArray, Blockchain_Item bcRoundItem, Fr t, GlobalParams globalParams)
      {
        //Init(BLS12_381);
        //ETHmode();
        bool check = false;
        var proofToBeVerify = bcRoundItem.proof[j];
        //controllo (1) - VERIFICA DELLA CHIAVE PK DELLE PROVE
        var PKj_sum = proofToBeVerify.left.PK.Add(proofToBeVerify.right.PK);
        check = bcRoundItem.pp.PK.Equals(PKj_sum);
        if (!check) return false;

        PK_T_y_Item tupleToBeVerify = null;
        switch (rndBitArray[j])
        {
          case 0:
            tupleToBeVerify = proofToBeVerify.left;
            break;
          case 1:
            tupleToBeVerify = proofToBeVerify.right;
            break;
          default:
            throw new Exception("b array contain invalid values!");
        }

        //controllo (2) - VERIFICA dei T attraverso in base al vettore di bit di casualita scelto dal verifier
        var T_temp = new G2();
        T_temp.Mul(globalParams.g2, t);   //Ti=g2^ti
        check = tupleToBeVerify.T.Equals(T_temp);
        if (!check) return false;

        //controllo (3)
        //HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))      
        var HC = CryptoUtils.H1(round);

        var Z_temp = new GT();
        var e = new GT();
        e.Pairing(HC, globalParams.PKLOE);   // e(H1(C),PKL)
        Z_temp.Pow(e, t);            // Zi = e(H1(C),PKL)^ti
        if (!Z_temp.IsValid()) throw new Exception("Z_temp not valid!");

        byte[] Zbytes = Z_temp.Serialize();
        byte[] HashZ = CryptoUtils.GetSHA256(Zbytes); // H(Zi)                                                 

        var ZBigInt = new BigInteger(HashZ);
        var sk = ZBigInt.Xor(tupleToBeVerify.y);     //H(Zi) XOR y

        var PK_temp = globalParams.ecParams.G.Multiply(sk);
        check = tupleToBeVerify.PK.Equals(PK_temp);             //g^(〖sk〗_(j,b_j)^' )==〖PK〗_(j,b_j )

        return check;
      }

      /// <summary>
      /// Esegue la procedura di aggregazione delle chiavi pubbliche parziali per generare la chiave pubblica master
      /// </summary>
      /// <param name="round"></param>
      /// <param name="bc"></param>
      /// <param name="verifiedContributorNameList">Le parti per cui la prova NIZK è valida</param>
      /// <returns></returns>
      public static Org.BouncyCastle.Math.EC.ECPoint Aggregate(ulong round, List<string> verifiedContributorNameList)
      {
        Console.WriteLine("\n=== Calcolo di MPK_R - procedura di aggregazione delle chiavi parziali PK ===");
        // recupero solo gli item dei contributori onesti (la cui prova è corretta)
        var bcRoundItemList = _blockChain.Items.Where(s => s.round == round && verifiedContributorNameList.Contains(s.contributorName)).ToList();
        var i = 1;
        var MPK_R = bcRoundItemList[0].pp.PK;
        for (i = 1; i <= bcRoundItemList.Count - 1; i++)
        {
          MPK_R = MPK_R.Add(bcRoundItemList[i].pp.PK);
        }
        Console.WriteLine($"MPK_R: {MPK_R}");
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
      public static BigInteger Invert(ulong round, G1 sigmaLOE, ECDomainParameters ecParams, List<string> verifiedContributorNameList)
      {
        //Init(BLS12_381);
        //ETHmode();
        //G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");

        //Recupero i parametri dalla blockChain
        var contributorList = _blockChain.Items.Where(s => s.round == round && verifiedContributorNameList.Contains(s.contributorName)).ToList();
        var array_sk = new BigInteger[contributorList.Count];
        var i = 0;
        foreach (var contributor in contributorList)
        {
          var Z = new GT();
          Z.Pairing(sigmaLOE, contributor.pp.T); //Zi=e(sigmaR,Ti)
          if (!Z.IsValid()) throw new Exception("Zi not valid!");
          //Console.WriteLine($"Z: {Z.GetStr(16).Print()}");

          var Zbytes = Z.Serialize();
          var hashZ = CryptoUtils.GetSHA256(Zbytes); //H(Zi)
                                                     //Console.WriteLine($"Hash Z - SHA256: {BitConverter.ToString(hashZ).Replace("-", "")}");
          var ZBigInt = new BigInteger(hashZ);
          var sk = contributor.pp.y.Xor(ZBigInt);
          CryptoUtils.CheckValidKeyPair(contributor.pp.PK, sk, ecParams); //verifica la validita della coppia di chiavi generate per il round
          Console.WriteLine($"{contributor.contributorName} sk (tlcs): {sk.ToString(16)} (chiave segreta ricostruita)");
          Console.WriteLine($"=============================");

          array_sk[i++] = sk;
        }

        //aggrega le chiavi private parziali ricostruite di tutte le parti (i contributori) per ricostruire la chiave segreta sk_r
        var sk_r = array_sk[0];
        for (i = 1; i <= array_sk.Length - 1; i++)
        {
          sk_r = sk_r.Add(array_sk[i]).Mod(ecParams.N);
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
      public PK_T_y_Item left { get; set; } //0
      public PK_T_y_Item right { get; set; } //1
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
      public List<Blockchain_Item> PopByRound(ulong round)
      {
        return Items.Where(s => s.round == round).ToList();
      }
    }
    public class Blockchain_Item
    {
      public ulong round { get; set; }
      public string contributorName { get; set; }
      public PK_T_y_Item pp { get; set; }
      public Proof_ItemOnBlockchain[] proof { get; set; }
    }
  }
}