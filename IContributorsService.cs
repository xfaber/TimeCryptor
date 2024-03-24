using static mcl.MCL;

namespace TimeCryptor
{
    public interface IContributorsService
    {
      Fr Get_t_fromContributor(string contributorName, int proofId, int randomBit);
    }
}