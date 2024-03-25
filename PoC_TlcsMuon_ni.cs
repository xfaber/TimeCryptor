
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

      Init(BLS12_381);
      ETHmode();
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");

      _LOE = new LeagueOfEntropy(LeagueOfEntropy.KeyModeEnum.FromWeb);

      _blockChain = new Blockchain();

      //IMPOSTO LA CURVA ELLITTICA DA UTILIZZARE PER LA COPPIA DI CHIAVI DA GENERARE
      _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
      _globalParams.k = 3; //parametro di sicurezza per errore di solidità
      _globalParams.numeroContributori = 3;

      _contributors = null;

      Console.WriteLine("\n=== CONFIGURAZIONI GENERALI ===");
      Console.WriteLine($"numeroContributori: {_globalParams.numeroContributori}");
      Console.WriteLine($"parametro di sicurezza k: {_globalParams.k}");
      Console.WriteLine($"Curva ellittica scelta: {_globalParams.ecCurveName}");

      //IMPOSTO LA DATA FUTURA, RECUPERO LA DATA FUTURA      
      var futureDateTime = DateTime.Now.AddSeconds(10);
      var round = LeagueOfEntropy.GetRound(futureDateTime);
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

        //Crea l'array b dall'hash della stringa [〖PK,(〖PK〗_(j,b),T_(j,b),y_(j,b) )〗_(j∈[k],b∈{1,2} )]. 
        P.b = P.GetRandomArrayForProof(_globalParams.k);

        var bHonestParty = false;
        if (i == 2) bHonestParty = true;//simula un contributo non onesto
        P.PublishToBlockchain(verifyMode.NotInteractive, _blockChain, bHonestParty);        
        _contributors[i - 1] = P;
      }

      //PROCEDURA DI VERIFICA DELLE PROVE 
      Console.WriteLine("\n=== VERIFICA DELLE PROVE ===");
      IContributorsService servizio = new ContributorsService(_contributors);
      _smartContract = new SmartContract(servizio);
      var verifiedContributorNameList = _smartContract.Verify(verifyMode.NotInteractive, round, _blockChain, _globalParams);

      //PROCEDURA DI AGGREGAZIONE
      Console.WriteLine("\n=== AGGREGAZIONE - CALCOLO MPK_R ===");
      var MPK_R = _smartContract.Aggregate(round, _blockChain, verifiedContributorNameList);

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
      var sigmaLOE = _LOE.sigma;
      //if (sigmaLOE == null)  { Console.WriteLine($"SIGMA LOE non ancora disponibile! Attendere fino a {LeagueOfEntropy.GetDateFromRound(round).ToString("dd/MM/yyyy HH:mm:ss")}"); }
      while (sigmaLOE == null)
      {
        Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
        Thread.Sleep(1000);
        sigmaLOE = _LOE.sigma;
      }
      Console.WriteLine("...FIRMA LOE DISPONIBILE!");
      Console.WriteLine($"{((G1)sigmaLOE).GetStr(16)}");
      Console.WriteLine($"sigmaLOE: {((G1)sigmaLOE).ToCompressedPoint()}");


      //PROCEDURA DI INVERSIONE
      Console.WriteLine("\n=== INVERSIONE - CALCOLO DI sk_R ===");
      
      Console.Write("\n=== VERIFICA FIRMA LOE ===");
      var checkFirmaLOE = LeagueOfEntropy.VerifySign(round, (G1)sigmaLOE, _globalParams.PKLOE);
      if (!checkFirmaLOE) throw new Exception("Firma LOE non valida!");
      else Console.Write("\nFirma LOE valida!\n\n");

      Console.WriteLine("\n=== Calcolo della sk_R - procedura di aggregazione delle chiavi segrete parziali sk della parti ===");
      var sk_R = _smartContract.Invert(round, (G1)sigmaLOE, _blockChain, _globalParams);
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


    
  }
}