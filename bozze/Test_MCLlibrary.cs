﻿using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TimeCryptor.Classes;
using static mcl.MCL;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace TimeCryptor.bozze
{
    internal class Test_MCLlibrary
    {

        static int err = 0;
        static void assert(string msg, bool b)
        {
            if (b) return;
            Console.WriteLine("ERR {0}", msg);
            err++;
        }
        public static void Run_Test_Pairing_BLS12_381()
        {
            Init(BLS12_381);

            var t = new Fr();
            t.SetByCSPRNG();

            Console.WriteLine("TestPairing");
            G1 P = new G1();
            P.HashAndMapTo("123");
            G2 Q = new G2();
            Q.HashAndMapTo("1");
            Fr a = new Fr();
            Fr b = new Fr();
            a.SetStr("12345678912345673453", 10);
            b.SetStr("230498230982394243424", 10);
            G1 aP = new G1();
            G2 bQ = new G2();
            aP.Mul(P, a);
            bQ.Mul(Q, b);
            GT e1 = new GT();
            GT e2 = new GT();
            GT e3 = new GT();
            e1.Pairing(P, Q);   //e(P,Q)
            e2.Pairing(aP, Q);  //e(aP,Q) 
            e3.Pow(e1, a);      //e(P,Q)^a
            assert("e2.Equals(e3)", e2.Equals(e3)); // e(aP,Q) == e(P,Q)^a
            e2.Pairing(P, bQ);  //e(P,bQ)
            e3.Pow(e1, b);      //e(P,Q)^b
            assert("e2.Equals(e3)", e2.Equals(e3)); //e(P,bQ) == e(P,Q)^b

            e2.Pairing(aP, bQ); //e(aP,bQ)
            Fr ab = new Fr();
            ab.Mul(a, b);
            e3.Pow(e1, ab);      //e(P,Q)^ab
            assert("e2.Equals(e3)", e2.Equals(e3));

            if (err == 0)
            {
                Console.WriteLine("all tests succeed");
            }
            else
            {
                Console.WriteLine("err={0}", err);
            }
        }

        public static void Run_Test_Serialization()
        {
            ulong round;
            G2 pk;
            G1 sigma;
            //var round = LeagueOfEntropy.GetRound(DateTime.Now);
            round = 5928395;
            GetRandomSigma(round, out pk, out sigma);

            var verificaFirma = checkFirma(round, pk, sigma);
            Console.WriteLine($"verifica firma: {verificaFirma} ");

            var sigma2 = new G1();
            var ser = sigma.Serialize();
            sigma2.Deserialize(ser);
            var chk = sigma.Equals(sigma2);
            Console.WriteLine($"sigma==sigma2: {chk}");

            Console.WriteLine($"round : {round}");
            var sigma3 = new G1();
            var sigmaHexString = sigma.ToCompressedPoint();
            sigma3.Deserialize(CryptoUtils.FromHexStr(sigmaHexString));
            chk = sigma.Equals(sigma3);
            Console.WriteLine($"sigma : {sigmaHexString}");
            Console.WriteLine($"sigma3: {sigma3.ToCompressedPoint()}");
            Console.WriteLine($"sigma==sigma3: {chk}");

            var pk2 = new G2();
            var pkHexString = pk.ToCompressedPoint();
            pk2.Deserialize(CryptoUtils.FromHexStr(pkHexString));
            chk = pk.Equals(pk2);
            Console.WriteLine($"pk : {pkHexString}");
            Console.WriteLine($"pk2: {pk2.ToCompressedPoint()}");
            Console.WriteLine($"pk==pk2: {chk}");
        }

        public static void Run_Test_CheckFirma()
        {
            //Test di una firma BLS
            Init(BLS12_381);
            ETHmode();

            //https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
            //https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/5928395
            Console.WriteLine("=== KEYS AND SIGNS FROM DRAND (SCHEMA: bls-unchained-g1-rfc9380) ===");
            ulong round = 5928395;
            var pkHexString = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
            var sigmaHexString = "a5d07c0071b4e386b3ae09206522253c68fefe8490ad59ecc44a7dd0d0745be91da5779e2247a82403fbc0cb9a34cb61";
            checkFirma(round, pkHexString, sigmaHexString);

            //https://testnet-api.drand.cloudflare.com/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/public/11775741
            //https://testnet-api.drand.cloudflare.com/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/public/11775741
            Console.WriteLine("=== KEYS AND SIGNS FROM DRAND (SCHEMA: bls-unchained-on-g1) ===");
            round = 11775741;
            pkHexString = "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13";
            sigmaHexString = "82036f6bcd6f626ba4526edb9918a296877579707f49a494723d865d27d42d84dee9cce84a37c21fe6d365ad9fae75db";
            checkFirma(round, pkHexString, sigmaHexString);

            Console.WriteLine("=== keys and signs randomly generated by custom method ===");
            G2 pk;
            G1 sigma;
            round = LeagueOfEntropy.GetRound(DateTime.Now);
            GetRandomSigma(round, out pk, out sigma);
            pkHexString = pk.ToCompressedPoint();
            sigmaHexString = sigma.ToCompressedPoint();
            checkFirma(round, pkHexString, sigmaHexString);
        }
        public static bool checkFirma(ulong round, G2 pk, G1 sigma)
        {
            Init(BLS12_381);
            ETHmode();

            var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
            var g2 = new G2();
            g2.SetStr(g2Str, 16);

            var h = CryptoUtils.H1(round);

            var e1 = new GT();
            e1.Pairing(sigma, g2);

            var e2 = new GT();
            e2.Pairing(h, pk);

            var retCheck = e1.Equals(e2);
            return retCheck;
        }

        public static void checkFirma(ulong round, string pkHexString, string sigmaHexString)
        {
            Console.WriteLine($"round: {round}");
            var pk = new G2();
            pk.Deserialize(CryptoUtils.FromHexStr(pkHexString));
            Console.WriteLine($"pkHexString:{pkHexString}");
            Console.WriteLine($"pk: {pk.ToCompressedPoint()}");
            Console.WriteLine($"pk isValid: {pk.IsValid()} ");
            Console.WriteLine($"pk isZero: {pk.IsZero()} ");

            var sigma = new G1();
            sigma.Deserialize(CryptoUtils.FromHexStr(sigmaHexString));
            Console.WriteLine($"sigmaHexString:{sigmaHexString}");
            Console.WriteLine($"sigma: {sigma.ToCompressedPoint()}");
            Console.WriteLine($"sigma isValid: {sigma.IsValid()} ");
            Console.WriteLine($"sigma isZero: {sigma.IsZero()} ");

            var chk = checkFirma(round, pk, sigma);
            Console.WriteLine($"=== CHECK SIGN: {chk} ===\n\n");
        }
        private static void GetRandomSigma(ulong round, out G2 pk, out G1 sigma)
        {
            //Test di una firma BLS
            Init(BLS12_381);
            ETHmode();

            var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
            var g2 = new G2(); //Zp
            g2.SetStr(g2Str, 16);

            //sceglie una chiave privata casuale
            var sk = new Fr();
            sk.SetByCSPRNG();
            Console.WriteLine($"sk: {sk.GetStr(16)}");

            //genera la chiave pubblica su G2 con la chiave privata casuale scelta 
            pk = new G2();
            pk.Mul(g2, sk);

            //firma il messaggio s = sk H(msg)
            var h = CryptoUtils.H1(round);
            sigma = new G1();
            sigma.Mul(h, sk);

            var e1 = new GT();
            e1.Pairing(sigma, g2);

            var e2 = new GT();
            e2.Pairing(h, pk);
        }
        public static void Run_Test_SerializeDeserialize()
        {
            Init(BLS12_381);
            ETHmode();
            var now = DateTime.Now;
            Console.WriteLine($"Data corrente: {now.ToString("dd/MM/yyyy HH:mm:ss")} round:{LeagueOfEntropy.GetRound(now)}");
            var span = new TimeSpan(0, 0, 3);
            var futureDateTime = now.Subtract(span);
            var round = LeagueOfEntropy.GetRound(futureDateTime);
            Console.WriteLine($"Data futura impostata: {futureDateTime.ToString("dd/MM/yyyy HH:mm:ss")} round:{round}");

            var LOE = new LeagueOfEntropy(LeagueOfEntropy.ReqDataModeEnum.FromLocal, round);
            var sigmaLOE = LOE.GetSigma(round);
            while (sigmaLOE == null)
            {
                Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")} -> firma LOE non disponibile, attendo...");
                Thread.Sleep(1000);
                sigmaLOE = LOE.GetSigma(round);
            }

            var checkFirma = LeagueOfEntropy.VerifySign(round, (G1)sigmaLOE, LOE.pk);
            Console.Write($"Firma LOE {(checkFirma ? "valida" : "NON valida")}");

            var sigmaLOE2 = new G1();
            sigmaLOE2.Deserialize(((G1)sigmaLOE).Serialize());
            var chk = sigmaLOE.Equals(sigmaLOE2);
            Console.WriteLine($"sigmaLOE==sigmaLOE2: {chk}");
            /*
            var sigmaLOEcompressed = sigmaLOE.ToCompressedPoint();
            Console.WriteLine($"sigmaLOE: {sigmaLOEcompressed.ToLower()}");
            var sigmaLOE2 = new G1();
            sigmaLOE2.SetStr(sigmaLOEcompressed, 16);
            var chk = sigmaLOE.Equals(sigmaLOE2);    
            */

        }
    }
}
