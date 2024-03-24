namespace TimeCryptor
{
  internal class Program
  {
    static void Main(string[] args)
    {
      //PoC_TLP.Run_PoC();            //Esegue il protocollo TLP

      //PoC_Tlock.Run_PoC();          //Esegue il protocollo Tlock

      PoC_TlcsMuon_i.Run_PoC();       //Esegue il protocollo TLCS Muon in versione interattiva

      //PoC_TlcsMuon_ni.Run_PoC();    //Esegue il protocollo TLCS Muon in versione NON interattiva

      //TEST VARI

      //Test_TimelockZone.Run_Test_ValidationKeys();

      //Test_MCLlibrary.Run_Test_Pairing_BLS12_381();
      //Test_MCLlibrary.Run_Test_SerializeDeserialize();
      //Test_MCLlibrary.Run_Test_Serialization();
      //Test_MCLlibrary.Run_Test_CheckFirma();

      //Test_LOE.Run_Test_Firma();
    }
  }
}
