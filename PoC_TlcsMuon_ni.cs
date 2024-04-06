using Org.BouncyCastle.Crypto.Parameters;
using TimeCryptor.Classes;
using static mcl.MCL;

namespace TimeCryptor
{
    public static class PoC_TlcsMuon_ni
  {
    static LeagueOfEntropy _LOE;
    static Blockchain _blockChain;
    static SmartContract _smartContract;
    static GlobalParams _globalParams;
    static Contributor[] _contributors;

    //Crea una coppia di chiavi per la curva ellittica scelta ed effettua una cifratura/decifratura di un messaggio con ECIES
    public static void Run_PoC()
    {
      Console.WriteLine("======================================================");
      Console.WriteLine("=== PoC === TLCS Muon - versione NON interattiva - ===");
      Console.WriteLine("======================================================");

      #region CONFIGURAZIONI GENERALI 
      Init(BLS12_381);
      ETHmode();
      #endregion

      #region IMPOSTAZIONE PARAMETRI POC (MESSAGGIO DA CIFRARE, DATA FUTURA e RECUPERO DEL NUMERO DI ROUND)
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"); //DST da impostare in base alla chain drand da utilizzare 
      //G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain (quelle non conformi a RFC rfc9380) viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2
      var MUON_VerifyMode = VerifyModeEnum.NotInteractive;
      var LOE_ReqDataMode = LeagueOfEntropy.ReqDataModeEnum.FromWeb;
      
      var message = "Hello TLE!";
      var futureDateTime = DateTime.Now.AddSeconds(10);
      var round = LeagueOfEntropy.GetRound(futureDateTime);
      Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");
      #endregion

      #region ISTANZE DELLE CLASSI SPECIFICHE
      
      _LOE = new LeagueOfEntropy(LOE_ReqDataMode, round);

      _blockChain = new Blockchain();

      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE
      _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
      _globalParams.k = 3; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;
      _globalParams.PKLOE = _LOE.pk;

      _contributors = new Contributor[_globalParams.numeroContributori];

      IContributorsService servizio = new ContributorsService(_contributors);
      _smartContract = new SmartContract(servizio);

      Console.WriteLine("\n=== CONFIGURAZIONI GENERALI ===");
      Console.WriteLine($"keyMode: {LOE_ReqDataMode}");
      Console.WriteLine($"numeroContributori: {_globalParams.numeroContributori}");
      Console.WriteLine($"parametro di sicurezza k: {_globalParams.k}");
      Console.WriteLine($"Curva ellittica scelta: {_globalParams.ecCurveName}");
      #endregion

      #region GENERAZIONE PARAMETRI PUBBLICI E PUBBLICAZIONE SULLA BLOCKCHAIN      
      Console.WriteLine("\n=== GENERAZIONE PARAMETRI PUBBLICI ===");
      for (int i = 1; i <= _globalParams.numeroContributori; i++)
      {
        var P = new Contributor($"P{i}", _globalParams.ecParams, _globalParams.k, round);
        P.SetPublicParams(round, _globalParams.PKLOE, MUON_VerifyMode);

        var bHonestParty = true; //permette di simulare un contributore non onesto, se bHonestParty=false il contributore pubblicherà una chiave falsa, non coerente con le prove
        if (i == 2) bHonestParty = false;
        P.PublishToBlockchain(MUON_VerifyMode, _blockChain, bHonestParty);
        _contributors[i - 1] = P;
      }
      #endregion

      #region VERIFICA DELLE PROVE
      Console.WriteLine("\n=== VERIFICA DELLE PROVE ===");
      var verifiedContributorNameList = _smartContract.Verify(MUON_VerifyMode, round, _blockChain, _globalParams);
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
      
      var cipherText = ECIES.Encrypt(message, keyPairSender.Private, publicKeyParameters);
      var cipherTextString = Convert.ToBase64String(cipherText);
      Console.WriteLine($"Testo originale: {message}");
      Console.WriteLine($"Testo cifrato: {cipherTextString}");
      Console.WriteLine($"Blocco temporale fino a : {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")}");
      #endregion

      #region RECUPERO LA FIRMA BLS DI LOE
      Console.WriteLine("\n=== RECUPERO LA FIRMA LOE ===");
      var sigmaLOE = _LOE.GetSigma(round);
      while (sigmaLOE == null)
      {
        Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
        Thread.Sleep(2000);
        sigmaLOE = _LOE.GetSigma(round);
      }
      Console.WriteLine("...FIRMA LOE DISPONIBILE!");
      Console.WriteLine($"{((G1)sigmaLOE).GetStr(16)}");
      Console.WriteLine($"sigmaLOE: {((G1)sigmaLOE).ToCompressedPoint()}");
      #endregion

      #region INVERSIONE - CALCOLO DI sk_R
      Console.WriteLine("\n=== INVERSIONE - CALCOLO DI sk_R ===");
      
      Console.Write("\n=== VERIFICA FIRMA LOE ===");
      var checkFirmaLOE = LeagueOfEntropy.VerifySign(round, (G1)sigmaLOE, _globalParams.PKLOE);
      if (!checkFirmaLOE) throw new Exception("Firma LOE non valida!");
      else Console.Write("\nFirma LOE valida!\n\n");

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
      Console.WriteLine($"Testo decifrato: plainText==message? {(plainText==message?"YES":"NO!")}"); 
      #endregion
    }
  }
}