namespace TimeCryptor.Classes
{
  public class Blockchain
    {
        public List<Blockchain_Item> Items = null;
        public Blockchain()
        {
            Items = new List<Blockchain_Item>();
        }
        public void Put(Blockchain_Item item)
        {
            Items.Add(item);
        }
        public Blockchain_Item PopByContributorName(string cName)
        {
            return Items.Single(s => s.contributorName == cName);
        }
        public List<Blockchain_Item> PopByRound(ulong round)
        {
            return Items.Where(s => s.round == round).ToList();
        }
    }

    public class Blockchain_Item
    {
        public string contributorName { get; set; }
        public ulong round { get; set; }
        public PK_T_y_Item pp { get; set; }
        public Proof_Item[] proof { get; set; }
    }

}
