using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;

namespace TimeCryptor
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
    public static void Run_TestPairing_BLS12_381()
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

    public static void RunTest_SerializeDeserialize()
    {
      /*
      Console.WriteLine($"sigmaLOE: {BitConverter.ToString(((G1)sigmaLOE).Serialize()).Replace("-", string.Empty).ToLower()}");
      var ser = BitConverter.ToString(((G1)sigmaLOE).Serialize()).Replace("-", string.Empty).ToLower();
      var sigmaLOE2 = new G1();
      sigmaLOE2.SetStr(ser, 16);
      var chk = sigmaLOE.Equals(sigmaLOE2);
      */
    }
  }
}
