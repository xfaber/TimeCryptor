namespace TimeCryptor
{
  internal class Program
  {
    static void Main(string[] args)
    { 
      //POC

      //PoC_TLP.Run_PoC();          //Esegue il protocollo TLP

      //PoC_Tlock.Run_PoC();        //Esegue il protocollo Tlock (PoC in versione bozza)

      //PoC_TlcsMuon_i.Run_PoC();   //Esegue il protocollo TLCS Muon in versione interattiva

      PoC_TlcsMuon_ni.Run_PoC();    //Esegue il protocollo TLCS Muon in versione NON interattiva

      //TEST

      //Test_TimelockZone.Run_Test_ValidationKeys(); // Esegue il test di verifica e utilizzo delle chiavi generate dal servizio timelock.zone (versione alpha, il servizio da gennaio 2024 non risulta più attivo, viene utilizzata una lista di coppie di chiavi generate precedentemente)
      
      // ALTRI TEST
      //Test_TimelockZone.Run_Test_SchnorrSignature();
      
      //Test_MCLlibrary.Run_Test_Pairing_BLS12_381();
      //Test_MCLlibrary.Run_Test_SerializeDeserialize();
      //Test_MCLlibrary.Run_Test_Serialization();
      //Test_MCLlibrary.Run_Test_CheckFirma();

      //Test_LOE.Run_Test_Firma();
    }
  }
}
