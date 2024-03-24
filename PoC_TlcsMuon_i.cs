
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static mcl.MCL;
using static TimeCryptor.CryptoUtils;
using static TimeCryptor.Test_TimelockZone;

namespace TimeCryptor
{
  public static partial class PoC_TlcsMuon_i
  {
    static LeagueOfEntropy _LOE;
    static Blockchain _blockChain;
    static GlobalParams _globalParams;
    static Contributor[] _contributors;

    //Crea una coppia di chiavi per la curva ellittica scelta ed effettua una cifratura/decifratura di un messaggio con ECIES
    public static void Run_PoC()
    {
      Console.WriteLine("==================================================");
      Console.WriteLine("=== PoC === TLCS Muon - versione interattiva - ===");
      Console.WriteLine("==================================================");
      
      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"); //DST da impostare in base alla chain drand da utilizzare 
      //G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain (quelle non conformi a RFC drand viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2

      _LOE = new LeagueOfEntropy(LeagueOfEntropy.KeyModeEnum.FromLocal);

      _blockChain = new Blockchain();

      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE      
      _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
      _globalParams.k = 2; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;
      _contributors = null;

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

      //L'INSIEME DELLE PARTI GENERANO I PARAMETRI PUBBLICI E LI PUBBLICANO SULLA BLOCKCHAIN       
      _contributors = new Contributor[_globalParams.numeroContributori];
      Console.WriteLine("\n=== GENERAZIONE PARAMETRI PUBBLICI E PUBBLICAZIONE SULLA BLOCKCHAIN ===");
      for (int i = 1; i <= _globalParams.numeroContributori; i++)
      {
        var P = new Contributor($"P{i}", _globalParams.ecParams, _globalParams.k, round);
        P.SetPublicParams(round, _globalParams.PKLOE);

        var bHonestParty = true;
        if (i == 2) bHonestParty = false; //simula un contributo non onesto
        P.PublishToBlockchain(verifyMode.Interactive, _blockChain, bHonestParty);
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
      //var sk_R = SmartContract.Invert_simple(round, (G1)sigmaLOE, _globalParams.ecParams, verifiedContributorNameList);
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

          var check = false;
          for (int j = 0; j < _globalParams.k; j++)
          {
            //controllo (1) - VERIFICA DELLA CHIAVE PK DELLE PROVE
            var PKj_sum = bcRoundItem.proof[j].left.PK.Add(bcRoundItem.proof[j].right.PK);
            check = bcRoundItem.pp.PK.Equals(PKj_sum);
            if (!check) break;

            //Seleziona la tupla da verificare in base all'array dei bit di casualità
            PK_T_y_ItemExtended tupleToBeVerify = null;
            switch (rndBitArray[j])
            {
              case 0:
                tupleToBeVerify = bcRoundItem.proof[j].left;
                break;
              case 1:
                tupleToBeVerify = bcRoundItem.proof[j].right;
                break;
              default:
                throw new Exception("b array contain invalid values!");
            }

            //Simula l'interazione tra verifier e prover - il verifier richiede al prover il parametro privato t della prova che vuole verificare (in base al valore casuale da lui scelto nell'array di bit rndBitArray)
            tupleToBeVerify.t = Get_t_fromContributor(round, bcRoundItem.contributorName, j, rndBitArray[j]);

            check = SmartContract.VerifyTupleProof(round, tupleToBeVerify, _globalParams);
            if (!check) break;
          }
          //Se tutti i controlli (1)(2)(3) passano il contributore viene messo nella lista dei contributori validi
          if (check) verifiedContributorNameList.Add(bcRoundItem.contributorName);
          Console.WriteLine($"Parte {bcRoundItem.contributorName} - Prova {((check) ? "valida" : "NON valida!")}");
        }

        return verifiedContributorNameList;
      }

      /// <summary>
      /// verifica che le prove che accompagnano i parametri pubblici inviati dalle parti siano valide
      /// </summary>
      /// <param name="round"></param>
      /// <param name="bc"></param>
      public static bool VerifyTupleProof(ulong round, PK_T_y_ItemExtended tupleToBeVerify, GlobalParams globalParams)
      {
        bool check = false;

        //controllo (2) - VERIFICA dei T in base al vettore di bit di casualita scelto dal verifier
        var T_temp = new G2();
        T_temp.Mul(globalParams.g2, tupleToBeVerify.t);   //Ti=g2^ti
        check = tupleToBeVerify.T.Equals(T_temp);
        if (!check) return false;

        //controllo (3)
        //HashedRound=MAP_TO_POINT(SHA256(BIG_ENDIAN(round)))      
        var HC = CryptoUtils.H1(round);

        var Z_temp = new GT();
        var e = new GT();
        e.Pairing(HC, globalParams.PKLOE);   // e(H1(C),PKL)
        Z_temp.Pow(e, tupleToBeVerify.t);            // Zi = e(H1(C),PKL)^ti
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
      /// <param name="verifiedContributorNameList">Le parti per cui la prova è valida</param>
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
      public static BigInteger Invert(ulong round, G1 sigmaLOE, Blockchain bc, GlobalParams globalParams)
      {
        //Recupero i parametri dalla blockChain
        var bcRoundItemList = bc.Items.Where(s => s.round == round).ToList();
        var array_sk = new BigInteger[bcRoundItemList.Count];
        var i = 0;
        foreach (var bcRoundItem in bcRoundItemList)
        {
          Console.WriteLine($"\n=== RICOSTRUZIONE CHIAVE SEGRETA PARZIALE PARTE {bcRoundItem.contributorName} ===");
          var check = false;
          for (int j = 0; j < globalParams.k; j++)
          {
            var sk1 = GetSk(bcRoundItem.proof[j].left, sigmaLOE);
            var PK1_temp = globalParams.ecParams.G.Multiply(sk1);
            var sk2 = GetSk(bcRoundItem.proof[j].right, sigmaLOE);
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
          if (array_sk[i] != null) sk_r = sk_r.Add(array_sk[i]).Mod(globalParams.ecParams.N);
        }
        return sk_r;
      }
      public static BigInteger GetSk(PK_T_y_ItemExtended tupleToBeVerify, G1 sigmaLOE)
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

      /// <summary>
      /// Esegue la procedura di inversione della chiave pubblica 
      /// </summary>
      /// <param name="round"></param>
      /// <param name="sigmaLOE"></param>
      /// <param name="bc"></param>
      /// <param name="ecParams"></param>
      /// <returns></returns>
      /// <exception cref="Exception"></exception>
      /// 
      public static BigInteger Invert_simple(ulong round, G1 sigmaLOE, ECDomainParameters ecParams, List<string> verifiedContributorNameList)
      {
        //Recupero i parametri dalla blockChain
        var bcRoundItemList = _blockChain.Items.Where(s => s.round == round && verifiedContributorNameList.Contains(s.contributorName)).ToList();
        var array_sk = new BigInteger[bcRoundItemList.Count];
        var i = 0;
        foreach (var bcRoundItem in bcRoundItemList)
        {
          var Z = new GT();
          Z.Pairing(sigmaLOE, bcRoundItem.pp.T); //Zi=e(sigmaR,Ti)
          if (!Z.IsValid()) throw new Exception("Zi not valid!");
          //Console.WriteLine($"Z: {Z.GetStr(16).Print()}");

          var Zbytes = Z.Serialize();
          var hashZ = CryptoUtils.GetSHA256(Zbytes); //H(Zi)
                                                     //Console.WriteLine($"Hash Z - SHA256: {BitConverter.ToString(hashZ).Replace("-", "")}");
          var ZBigInt = new BigInteger(hashZ);
          var sk = bcRoundItem.pp.y.Xor(ZBigInt);
          CryptoUtils.CheckValidKeyPair(bcRoundItem.pp.PK, sk, ecParams); //verifica la validita della coppia di chiavi generate per il round
          Console.WriteLine($"{bcRoundItem.contributorName} sk (tlcs): {sk.ToString(16)} (chiave segreta ricostruita)");
          Console.WriteLine($"=============================");

          array_sk[i++] = sk;
        }

        Console.WriteLine("\n=== AGGREGA LE CHIAVI PRIVATE PARZIALI DELLE PARTI ===");
        //aggrega le chiavi private parziali ricostruite di tutte le parti (i contributori) per ricostruire la chiave segreta sk_r
        var sk_r = array_sk[0];
        for (i = 1; i <= array_sk.Length - 1; i++)
        {
          sk_r = sk_r.Add(array_sk[i]).Mod(ecParams.N);
        }
        return sk_r;
      }
    }
  }
}