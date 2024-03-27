
using Org.BouncyCastle.Crypto.Parameters;
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
    static SmartContract _smartContract;
    static GlobalParams _globalParams;
    static Contributor[] _contributors;

    //Crea una coppia di chiavi per la curva ellittica scelta ed effettua una cifratura/decifratura di un messaggio con ECIES
    public static void Run_PoC()
    {
      Console.WriteLine("==================================================");
      Console.WriteLine("=== PoC === TLCS Muon - versione interattiva - ===");
      Console.WriteLine("==================================================");

      #region CONFIGURAZIONI GENERALI
      Console.WriteLine("\n=== CONFIGURAZIONI GENERALI ===");
      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"); //DST da impostare in base alla chain drand da utilizzare 
      //G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain (quelle non conformi a RFC rfc9380) viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2

      _LOE = new LeagueOfEntropy(LeagueOfEntropy.KeyModeEnum.FromLocal);
      _blockChain = new Blockchain();

      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE      
      _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
      _globalParams.k = 80; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;
      
      Console.WriteLine($"numeroContributori: {_globalParams.numeroContributori}");
      Console.WriteLine($"parametro di sicurezza k: {_globalParams.k}");
      Console.WriteLine($"Curva ellittica scelta: {_globalParams.ecCurveName}");
      #endregion

      # region IMPOSTAZIONE DATA FUTURA e RECUPERO IL NUMERO DI ROUND      
      var futureDateTime = DateTime.Now.AddSeconds(10); //blocco temporale 10 secondi
      ulong round = LeagueOfEntropy.GetRound(futureDateTime);
      Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");
      _LOE.Round = round;
      _globalParams.PKLOE = (G2)_LOE.pk;
      #endregion

      #region GENERAZIONE PARAMETRI PUBBLICI E PUBBLICAZIONE SULLA BLOCKCHAIN
      Console.WriteLine("\n=== GENERAZIONE PARAMETRI PUBBLICI E PUBBLICAZIONE SULLA BLOCKCHAIN ===");
      _contributors = new Contributor[_globalParams.numeroContributori];      
      for (int i = 1; i <= _globalParams.numeroContributori; i++)
      {
        var P = new Contributor($"P{i}", _globalParams.ecParams, _globalParams.k, round);
        P.SetPublicParams(round, _globalParams.PKLOE);

        var bHonestParty = false;
        if (i == 2) bHonestParty = true; //simula un contributo non onesto
        P.PublishToBlockchain(verifyMode.Interactive, _blockChain, bHonestParty);
        _contributors[i - 1] = P;
      }
      #endregion

      #region VERIFICA DELLE PROVE
      Console.WriteLine("\n=== VERIFICA DELLE PROVE ===");
      IContributorsService servizio = new ContributorsService(_contributors);
      _smartContract = new SmartContract(servizio);
      var verifiedContributorNameList = _smartContract.Verify(verifyMode.Interactive, round, _blockChain, _globalParams);
      #endregion

      #region AGGREGAZIONE - CALCOLO MPK_R
      Console.WriteLine("\n=== AGGREGAZIONE - CALCOLO MPK_R ===");
      var MPK_R = _smartContract.Aggregate(round, _blockChain, verifiedContributorNameList);
      #endregion

      #region CIFRATURA
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
      #endregion

      #region RECUPERO LA FIRMA LOE
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
      #endregion

      #region INVERSIONE - CALCOLO DI sk_R
      Console.WriteLine("\n=== INVERSIONE - CALCOLO DI sk_R ===");
      Console.WriteLine("\n=== Calcolo della sk_R - procedura di aggregazione delle chiavi segrete parziali sk della parti ===");
      var sk_R = _smartContract.Invert(round, (G1)sigmaLOE, _blockChain, _globalParams);
      Console.WriteLine($"sk_R: {sk_R.ToString(16)}");
      CryptoUtils.CheckValidKeyPair(MPK_R, sk_R, _globalParams.ecParams);
      #endregion

      #region DECIFRATURA
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
      #endregion
    }
  }
}