
using Org.BouncyCastle.Crypto.Parameters;
using static mcl.MCL;

namespace TimeCryptor.Classes
{
    public class GlobalParams
    {
        public GlobalParams(CryptoUtils.ECname ecCurveEnum)
        {
            var g2Str16 = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
            var gen_g2 = new G2();
            gen_g2.SetStr(g2Str16, 16);
            g2 = gen_g2;
            ecCurveName = ecCurveEnum;

            if (ecCurveEnum == CryptoUtils.ECname.BabyJubjub) ecParams = CryptoUtils.GetEcDomainParametersByCustomData(ecCurveName.ToString().ToLower());
            else ecParams = CryptoUtils.GetEcDomainParametersByEcName(ecCurveName.Description());
        }

        public CryptoUtils.ECname ecCurveName { get; set; }
        public ECDomainParameters ecParams { get; set; }
        public int k { get; set; } //parametro di sicurezza per errore di solidità
        public int numeroContributori { get; set; }
        public G2 g2 { get; set; }
        public G2 PKLOE { get; set; }
    }
    public enum verifyMode
    {
        Interactive,
        NotInteractive
    }
}
