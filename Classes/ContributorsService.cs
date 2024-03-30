using static mcl.MCL;

namespace TimeCryptor.Classes
{
    /// <summary>
    /// Servizio per il recupero dei dati dai contributori
    /// </summary>
    public class ContributorsService : IContributorsService
    {
        Contributor[] _contributors;
        public ContributorsService(Contributor[] contributors)
        {
            _contributors = contributors;
        }
        public Fr Get_t_fromContributor(string contributorName, int proofId, int randomBit)
        {
            Fr t;
            var contributor = _contributors.Single(s => s.Name == contributorName);
            switch (randomBit)
            {
                case 0:
                    t = contributor.proof[proofId].left.t;
                    break;
                case 1:
                    t = contributor.proof[proofId].right.t;
                    break;
                default:
                    throw new Exception("rndBitArray array contain invalid values!");
            }
            return t;
        }
    }
}
