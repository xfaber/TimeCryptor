namespace TimeCryptor
{
  internal class Program
  {
    static void Main(string[] args)
    {
      //PoC_RSW_Puzzle.Run_PoC();

      //PoC_Tlock.Run_PoC();
      
      //var LOE = new LeagueOfEntropy();
      //var PK = LOE.GetPublicKey();

      PoC_TlcsMuon_i.Run_PoC();
      //PoC_TlcsMuon_ni.Run_PoC();
      //Test_TimelockZone.Run_Test_ValidationKeys();

      //Test_MCLlibrary.Run_Test_Pairing_BLS12_381();
      //Test_MCLlibrary.Run_Test_SerializeDeserialize();
      //Test_MCLlibrary.Run_Test_Serialization();
      //Test_MCLlibrary.Run_Test_CheckFirma();

      //Test_LOE.Run_Test_Firma();
    }
  }
}
