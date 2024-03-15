namespace TimeCryptor
{
  public class TlcsKeyPairs
  { public tlcskeypair[] keypairs { get; set; }
  }
  public class tlcskeypair
  {
    public int round { get; set; }
    public int scheme { get; set; }
    public int pubkey_time { get; set; }
    public string public_key { get; set; }
    public string private_key { get; set; }
    public string public_key_pem { get; set; }
    public string private_key_pem { get; set; }
    public string private_key_pkcs8 { get; set; }
  }
}