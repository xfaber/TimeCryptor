using static mcl.MCL;

namespace TimeCryptor.Classes
{
    public class PK_T_y_ItemExtended : PK_T_y_Item
    {
        public Fr t { get; set; } //da usare solo nelle proof e deve essere cancellato dalal tupla pubblicata sulla blockchain
    }
}
