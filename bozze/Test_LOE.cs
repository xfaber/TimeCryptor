﻿using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;

namespace TimeCryptor.bozze
{
    public static class Test_LOE
    {
        /// <summary>
        /// verifica che e(SIG_LOE,G2) = e(H(C),PK_LOE) dove C = SHA256(numero di round)
        /// </summary>
        /// <param name="round"></param>
        /// <param name="sigma"></param>
        /// <param name="pk"></param>
        /// <returns></returns>
        public static bool checkFirma(ulong round, G1 sigma, G2 pk)
        {
            Init(BLS12_381);
            ETHmode();
            G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");

            var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
            var g2 = new G2(); //Zp
            g2.SetStr(g2Str, 16);

            var h = CryptoUtils.H1(round);

            var e1 = new GT();
            e1.Pairing(sigma, g2);

            var e2 = new GT();
            e2.Pairing(h, pk);

            var retCheck = e1.Equals(e2);
            return retCheck;
        }

        public static void Run_Test_Firma()
        {
            Init(BLS12_381);
            ETHmode();
            G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
            /*
            {
              "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
              "period": 3,
              "genesis_time": 1692803367,
              "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
              "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
              "schemeID": "bls-unchained-g1-rfc9380",
              "metadata": {"beaconID": "quicknet"}
            }
            {
              "round": 5358915,
              "randomness": "ded576cc39a412bc7c66c6f4a530983f4894567ed27846fcca14909436308814",
              "signature": "95f058cbd1294bc3fa28647dabded06d50b543643fb04e1cb2c5b6204daf20935782f7cae5fa7718cf87b4c43d108842"
            }
            */
            ulong round = 5358915;
            var PKLOEstring = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
            var SigLOEString = "95f058cbd1294bc3fa28647dabded06d50b543643fb04e1cb2c5b6204daf20935782f7cae5fa7718cf87b4c43d108842";
            var randomness = "ded576cc39a412bc7c66c6f4a530983f4894567ed27846fcca14909436308814"; //randomness =sha256(SigLOEString)

            //var round = 11064067;
            //var PKLOEstring = "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13";      
            //var SigLOEString = "b413cddd656559eaddcc5b1bf6e55f842b4cf878a1bf315e60e3b9693f57e2397ff63d5dc9c76f464cbaf536c9fdf752";
            //var randomness = "4a8ff98e685c0acf9284b7226ffd740d0dc1be990a2e5fe4b51778ba2b2f6977"; //randomness =sha256(SigLOEString)

            //Calcolo l'hash 256 del round
            var HC = CryptoUtils.H1(round);
            Console.WriteLine($"HC: {HC.GetStr(16)}");

            var SigLOE = new G1();
            var bytes_SKLOE = CryptoUtils.FromHexStr(SigLOEString);
            SigLOE.Deserialize(bytes_SKLOE);
            if (!SigLOE.IsValid()) throw new Exception("SigLOEstring not valid!");

            //var g2Str10 = "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582";
            var g2Str16 = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
            var g2 = new G2(); //Zp
            g2.SetStr(g2Str16, 16);
            var e1 = new GT();
            e1.Pairing(SigLOE, g2);

            var bytes_pkloe = CryptoUtils.FromHexStr(PKLOEstring);
            var PKLOE = new G2();
            PKLOE.Deserialize(bytes_pkloe);
            if (!PKLOE.IsValid()) throw new Exception("PKLOEstring not valid!");
            Console.WriteLine($"PKLOE: {PKLOE.GetStr(16)}");

            var e2 = new GT();
            e2.Pairing(HC, PKLOE);

            var check = e1.Equals(e2); // check e1==e2
            Console.WriteLine($"check: {check}");
        }
    }
}