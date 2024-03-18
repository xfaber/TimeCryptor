namespace TimeCryptor
{
  public class KeypairsGenerationData
  {
    public Check_Tx check_tx { get; set; }
    public Deliver_Tx deliver_tx { get; set; }
    public string hash { get; set; }
    public string height { get; set; }
  }

  public class Check_Tx
  {
    public int code { get; set; }
    public object data { get; set; }
    public string log { get; set; }
    public string info { get; set; }
    public string gas_wanted { get; set; }
    public string gas_used { get; set; }
    public object[] events { get; set; }
    public string codespace { get; set; }
    public string sender { get; set; }
    public string priority { get; set; }
    public string mempool_error { get; set; }
  }

  public class Deliver_Tx
  {
    public int code { get; set; }
    public object data { get; set; }
    public string log { get; set; }
    public string info { get; set; }
    public string gas_wanted { get; set; }
    public string gas_used { get; set; }
    public object[] events { get; set; }
    public string codespace { get; set; }
  }
}