using Org.BouncyCastle.Math;
using static mcl.MCL;

namespace TimeCryptor
{
  public class SmartContract
  {
    private IContributorsService _servizio;
    public SmartContract(IContributorsService servizio)
    {
      _servizio = servizio;
    }
    public int[] ChooseRandomBitArray(int k)
    {
      //Il verifier sceglie un array di k bit casuali (usando gli interi 0 e 1)
      return ChooseRandomArray(k, 1);
    }

    public int[] ChooseRandomArray(int k, int maxValue)
    {
      //sceglie un array di k valori interi asuali
      var b = new int[k];
      Random r = new Random();
      while (b.All(item => item == 0)) //per escludere la scelta di tutti i valori 0
      //while (b.Distinct().Count()==1) //per escludere la scelta di tutti i valori uguali
      {
        for (int i = 0; i < b.Length; i++)
        {
          b[i] = r.Next(0, maxValue + 1);
        }
      }
      return b;
    }

    /// <summary>
    /// effettua la verifica delle prove che accompagnano i parametri pubblici inviati dalle parti
    /// </summary>
    /// <param name="round"></param>
    /// <param name="blockChain"></param>
    /// <param name="globalParams"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    public List<string> Verify(verifyMode vm, ulong round, Blockchain blockChain, GlobalParams globalParams)
    {      
      //lista dei contributori validi, per cui la verifica delle prove ha dato esito positivo
      var verifiedContributorNameList = new List<string>();
      //Recupera i dati dei parametri pubblici pubblicati dai contributori sulla blockchain 
      var bcRoundItemList = blockChain.PopByRound(round);
      foreach (var bcRoundItem in bcRoundItemList)
      {
        Console.WriteLine($"--Verifica prova di {bcRoundItem.contributorName}--");
        int[] rndBitArray;
        if (vm == verifyMode.Interactive)
          rndBitArray = ChooseRandomBitArray(globalParams.k);
        else
          rndBitArray = GetRandomArrayForProof(bcRoundItem, globalParams.k);

        Console.WriteLine($"Random bit array: {String.Join(',',rndBitArray)}");
        var check = false;
        for (int j = 0; j < globalParams.k; j++)
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

          if (vm == verifyMode.Interactive)
          {
            //Simula l'interazione tra verifier e prover - il verifier richiede al prover il parametro privato t della prova che vuole verificare (in base al valore casuale da lui scelto nell'array di bit rndBitArray)
            Console.WriteLine($"Chiama il servizio per recuperare il parametro t dal contributore {bcRoundItem.contributorName} per {j} di k {(rndBitArray[j]==1?"right":"left")}");
            tupleToBeVerify.t = _servizio.Get_t_fromContributor(bcRoundItem.contributorName, j, rndBitArray[j]);
          }

          check = VerifyTupleProof(round, tupleToBeVerify, globalParams);
          if (!check) break;
        }

        //Se tutti i controlli (1)(2)(3) passano il contributore viene messo nella lista dei contributori validi
        if (check) verifiedContributorNameList.Add(bcRoundItem.contributorName);
        Console.WriteLine($"Parte {bcRoundItem.contributorName} - Prova {((check) ? "valida" : "NON valida!")}");
      }
      Console.WriteLine($"Parti valide: {verifiedContributorNameList.Count}/{globalParams.numeroContributori}");
      return verifiedContributorNameList;
    }

    /// <summary>
    /// verifica che le prove che accompagnano i parametri pubblici inviati dalle parti siano valide
    /// </summary>
    /// <param name="round"></param>
    /// <param name="bc"></param>
    public bool VerifyTupleProof(ulong round, PK_T_y_ItemExtended tupleToBeVerify, GlobalParams globalParams)
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
      Z_temp.Pow(e, tupleToBeVerify.t);    // Zi = e(H1(C),PKL)^ti
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
    public Org.BouncyCastle.Math.EC.ECPoint Aggregate(ulong round, Blockchain bc, List<string> verifiedContributorNameList)
    {
      Console.WriteLine("\n=== CALCOLO DI MPK_R - AGGREGAZIONE DELLE CHIAVI PUBBLICHE PARZIALI DELLE PARTI ===");
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
    public BigInteger Invert(ulong round, G1 sigmaLOE, Blockchain bc, GlobalParams globalParams)
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
    public BigInteger GetSk(PK_T_y_ItemExtended tupleToBeVerify, G1 sigmaLOE)
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
    public int[] GetRandomArrayForProof(Blockchain_Item bcItem, int k)
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
      var retArray = new int[k];
      for (int i = 0; i < k; i++)
      {
        retArray[i] = (bitString[i] == '1') ? 1 : 0;
      }
      return retArray;
    }
  }
}
