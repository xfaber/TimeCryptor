using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Math;
using System;
using System.Diagnostics;
using static mcl.MCL;

namespace TimeCryptor
{
  public class LeagueOfEntropy
  {
    public enum KeyModeEnum
    {
      FromWeb, //recupera chiave PK e firma BLS dal servizio rest api su internet
      FromLocal //crea chiavi firma con chiavi generate in locale
    }
    public LeagueOfEntropy(KeyModeEnum keyMode, string drandNetworkHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
    {
      this.DrandNetworkHash = drandNetworkHash;
      this.KeyMode = keyMode;
    }

    public KeyModeEnum KeyMode { get; private set; }
    private G2? _pk;
    public G2? pk
    {
      get
      {
        if (_pk == null)
        {
          if (this.KeyMode == KeyModeEnum.FromWeb)
            Set_PKLOE_FromWeb();
          else
            Set_LOE_Data_FromLocal();
        }
        return _pk;
      }
      set { _pk = value; }
    }
    private Fr sk { get; set; }
    public ulong Round { get; set; }

    private G1? _sigma;
    public G1? sigma
    {
      get
      {
        if (_sigma == null)
        {
          if (this.KeyMode == KeyModeEnum.FromWeb)
            SetSigmaFromWeb();
        }
        return _sigma;
      }
      set { _sigma = value; }
    }

    public string DrandNetworkHash { get; }

    public static bool checkFirma(ulong round, G1 sigma, G2 pk)
    {
      //Init(BLS12_381);
      //ETHmode();

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);

      var rbytes_le = BitConverter.GetBytes(round);   //--> little-endian
      var rbytes_be = rbytes_le.Reverse().ToArray();  //--> big-endian
      var rHash = CryptoUtils.GetSHA256(rbytes_be);
      var h = new G1();
      h.HashAndMapTo(rHash);

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
    public void Set_LOE_Data_FromLocal()
    {
      //Test di una firma BLS
      //Init(BLS12_381);
      //ETHmode();

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);

      //sceglie una chiave privata casuale
      var sk = new Fr();
      sk.SetByCSPRNG();

      //genera la chiave pubblica su G2 con la chiave privata casuale scelta 
      var pk = new G2(); //Zp
      pk.Mul(g2, sk);

      //firma il messaggio calcolando s = sk H(msg)      
      var h = CryptoUtils.H1(this.Round);
      var sigma = new G1();
      sigma.Mul(h, sk);

      var e1 = new GT();
      e1.Pairing(sigma, g2);

      var e2 = new GT();
      e2.Pairing(h, pk);

      var verificaFirma = e1.Equals(e2);
      Console.WriteLine($"\n=== PARAMETRI LOE ===");
      Console.WriteLine($"Round: {this.Round}");
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

    public void Set_PKLOE_FromWeb()
    {
      //RECUPERA LA CHIAVE DI ROUND
      //Init(BLS12_381);
      //ETHmode();

      //recupero la chiave pubblica della rete
      var url = $"https://api.drand.sh/{this.DrandNetworkHash}/info";
      var drandNetworkObj = GetData<DrandNetworkInfo>(url);
      if (drandNetworkObj == null) throw new Exception($"getPublicKey from drand network with hash {this.DrandNetworkHash} error!");

      var pk = new G2();
      pk.Deserialize(CryptoUtils.FromHexStr(drandNetworkObj.public_key));
      this.pk = pk;
    }

    public void SetSigmaFromWeb()
    {
      var url = $"https://api.drand.sh/{this.DrandNetworkHash}/public/{this.Round}";
      Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> recupero la firma LOE");
      var drandBeaconObj = GetData<DrandBeaconInfo>(url);
      if (drandBeaconObj != null)
      {
        var sig = new G1();
        sig.Deserialize(CryptoUtils.FromHexStr(drandBeaconObj.signature));
        var check = checkFirma(this.Round, sig, (G2)this.pk);
        this.sigma = sig;
      }
      else
      {
        Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile!");
        this.sigma = null;
      }
    }

    public static T GetData<T>(string url) where T : class
    {
      var client = new HttpClient();
      client.BaseAddress = new Uri(url);
      HttpResponseMessage response;
      using (var request = new HttpRequestMessage())
      {
        request.Method = HttpMethod.Get;
        request.RequestUri = new Uri(url);
        response = client.SendAsync(request).GetAwaiter().GetResult();
      }

      if (!response.IsSuccessStatusCode)
      {
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) //chiave non pronta!
          return null;
        else
        {
          var excMsg = $"Errore richiesta recupero dati drand network: \nStatus Code: {response.StatusCode} \nReasonPhrase: {response.ReasonPhrase} \nRequestMessage: {response.RequestMessage}";
          Console.WriteLine(excMsg);
          throw new Exception(excMsg);
        }
      }
      var retData = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
      var retJsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(retData);

      return retJsonObj;
    }

    /// <summary>
    /// Calcola il numero di round associato a una data futura specifica passata come parametro
    /// si assume di utilizzare la rete dranad Quicknet (con genesystime = 1692803367 e period = 3)
    /// Dati della rete recuperabili tramite questo link https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
    /// </summary>
    /// <param name="futureDateTime">Data futura</param>
    /// <returns></returns>
    public static ulong GetRound(DateTime futureDateTime)
    {
      const int drand_genesis_time = 1692803367; //drand quicknet genesis time
      const int period = 3;
      decimal futureDateTime_unix = ((DateTimeOffset)futureDateTime).ToUnixTimeSeconds();
      decimal round = ((futureDateTime_unix - drand_genesis_time) / period); //Valore intero minimo maggiore o uguale a round (arrotondamento divisione per eccesso es. 1.3 => 2)
      var ret = Math.Ceiling(round);
      return (ulong)ret;
    }

    public static ulong GetRound(DateTime? futureDateTime, int drand_genesis_time, int period)
    {
      if (futureDateTime == null) futureDateTime = DateTime.UtcNow;
      decimal futureDateTime_unix = ((DateTimeOffset)futureDateTime).ToUnixTimeSeconds();
      decimal round = ((futureDateTime_unix - drand_genesis_time) / period); //Valore intero minimo maggiore o uguale a round (arrotondamento divisione per eccesso es. 1.3 => 2)
      var ret = Math.Ceiling(round);
      return (ulong)ret;
    }

    public static DateTime GetDateFromRound(ulong round)
    {
      const int drand_genesis_time = 1692803367; //drand quicknet genesis time
      const int period = 3;
      var d = (round * period) + drand_genesis_time;
      var retDate = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(d));
      return retDate.DateTime.ToLocalTime();
    }

  
  }

  public class DrandBeaconInfo
  {
    public int round { get; set; }
    public string randomness { get; set; }
    public string signature { get; set; }
  }

  public class DrandNetworkInfo
  {
    public string public_key { get; set; }
    public int period { get; set; }
    public int genesis_time { get; set; }
    public string hash { get; set; }
    public string groupHash { get; set; }
    public string schemeID { get; set; }
    public Metadata metadata { get; set; }
  }

  public class Metadata
  {
    public string beaconID { get; set; }
  }
}
