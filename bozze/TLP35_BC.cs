using Org.BouncyCastle.Math;
using System.Text;

namespace TimeCryptor.bozze
{

  public static class TLP35_BC
  {
    public static void CreatePuzzle2019()
    {
      // Compute count of squarings to do each year
      BigInteger squaringsPerSecond = new BigInteger("3000", 10); // in 1999
      Console.WriteLine("Assumed number of squarings/second (now) = " + squaringsPerSecond);
      BigInteger secondsPerYear = new BigInteger("31536000", 10);
      BigInteger s = secondsPerYear.Multiply(squaringsPerSecond); // first year
      Console.WriteLine("Squarings (first year) = " + s);
      int years = 35; // was 35 for orignal LCS 35 puzzle
      double Moore = 1.58740105197; // = 2^(2/3) Moore's Law constant per year (used for LCS35 puzzle)
      double Peffers = 1.1000; // Estimate from Simon Peffers
      int growth = (int)(Moore * 10000);
      // (Note that this is also in code in a few lines as a constant.)
      // Method used for computing t for LCS35
      BigInteger t = BigInteger.Zero;
      for (int i = 1; i <= years; i++)
      { // do s squarings in year i
        t = t.Add(s); // apply Moore's Law to get number of squarings to do the next year                
        s = s.Multiply(new BigInteger(growth.ToString(), 10)).Divide(new BigInteger("10000", 10));
        Console.WriteLine($"Squarings for the year ({2019 + i}) t= {t} s= {s}");
      }

      // Method for 2019 puzzle: set t to 2**56
      int log2_t = 56;
      BigInteger t2 = BigInteger.One.ShiftLeft(log2_t);
      Console.WriteLine("t2 Squarings (total)=            " + t2);

      Console.WriteLine(" t Squarings (total)=            " + t);
      // Now generate RSA parameters
      int primelength = 1536;
      Console.WriteLine("Using " + primelength + "-bit primes.");
      BigInteger twoPower = BigInteger.One.ShiftLeft(primelength);

      var prand = CryptoUtils.GetRandomPrimeNumber(primelength);
      Console.WriteLine($"large random integer for prime p seed"); prand.Print();
      var qrand = CryptoUtils.GetRandomPrimeNumber(primelength);
      Console.WriteLine($"large random integer for prime q seed"); qrand.Print();

      //String pseed = getString("large random integer for prime p seed");
      //BigInteger prand = BigInteger.Parse(pseed);
      //String qseed = getString("large random integer for prime q seed");
      //BigInteger qrand = BigInteger.Parse(qseed);

      Console.WriteLine("Computing...");
      var FIVE = new BigInteger("5", 10);
      var p = new BigInteger("7", 10);
      var q = new BigInteger("11", 10);
      var n = new BigInteger("77", 10);
      var max_n = BigInteger.One.ShiftLeft(2 * primelength);
      var min_n = BigInteger.One.ShiftLeft(2 * primelength - 1);
      while (n.CompareTo(min_n) == -1 || n.CompareTo(max_n) == 1)
      {
        // Note that 5 has maximal order modulo 2^k (See Knuth)
        prand = prand.Add(ONE);
        p = FIVE.ModPow(prand, twoPower).NextProbablePrime();
        Console.WriteLine("p = " + p);
        qrand = qrand.Add(ONE);
        q = FIVE.ModPow(qrand, twoPower).NextProbablePrime();

        Console.WriteLine("q = " + q);
        n = p.Multiply(q);
        Console.WriteLine("n = " + n);
      }
      var pm1 = p.Subtract(ONE);
      var qm1 = q.Subtract(ONE);
      var phi = pm1.Multiply(qm1);
      Console.WriteLine("phi = " + phi);
      // Now generate final puzzle value w
      var u = TWO.ModPow(t, phi);
      var w = TWO.ModPow(u, n);
      Console.WriteLine("w (hex) = " + w.ToString());
      // Obtain and encrypt the secret message
      // Include seed for p as a check
      var sgen = new StringBuilder(getString("string for secret"));
      sgen = sgen.Append(" (seed value b for p = " + prand.ToString() + ")");
      Console.WriteLine("Puzzle secret = " + sgen);
      var secret = getBigIntegerFromStringBuffer(sgen);
      if (secret.CompareTo(n) > 0)
      { Console.WriteLine("Secret too large!"); return; }
      BigInteger z = secret.Xor(w);
      Console.WriteLine("z(hex) = " + z.ToString());

      // Write output to a file
      using (var pw = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + "puzzleoutput.txt"))
      {
        pw.WriteLine("Crypto-Puzzle for CSAIL 2019 Time Capsule.");
        pw.WriteLine("Created by Ronald L. Rivest. May 14, 2019.");
        pw.WriteLine();
        pw.WriteLine("(Successor to LCS 35 Crypto-Puzzle.)"); pw.WriteLine();
        pw.WriteLine("Puzzle parameters (all in decimal):"); pw.WriteLine();
        pw.Write("n = "); printBigInteger(n, pw); pw.WriteLine();
        pw.Write("t = "); printBigInteger(t, pw);
        pw.Write(" = 2 ** "); pw.Write(log2_t); pw.WriteLine(); pw.WriteLine();
        pw.Write("z = "); printBigInteger(z, pw); pw.WriteLine();
        pw.WriteLine("To solve the puzzle, first compute w = 2^(2^t) (mod n).");
        pw.WriteLine("Then exclusive-or the result with z.");
        pw.WriteLine("(Right-justify the two strings first.)");
        pw.WriteLine();
        pw.WriteLine("The result is the secret message (8 bits per character),");
        pw.WriteLine("including information that will allow you to factor n.");
        pw.WriteLine("(The extra information is a seed value b, such that ");
        pw.WriteLine("5^b (mod 2^1536) is just below a prime factor of n.)");
        pw.WriteLine(" ");
      }
      // Wait for input carriage return to pause before closing
      Console.Read();
    }

    public static void CreatePuzzleLCS35()
    {
      // Compute count of squarings to do each year
      BigInteger squaringsPerSecond = new BigInteger("3000", 10); // in 1999
      Console.WriteLine("Assumed number of squarings/second (now) = " + squaringsPerSecond);
      BigInteger secondsPerYear = new BigInteger("31536000", 10);
      BigInteger squaringsFirstYear = secondsPerYear.Multiply(squaringsPerSecond);
      Console.WriteLine("Squarings (first year) = " + squaringsFirstYear);
      int years = 35;
      BigInteger t = BigInteger.Zero;
      BigInteger s = squaringsFirstYear;
      for (int i = 1999; i <= 1998 + years; i++)
      { // do s squarings in year i
        t = t.Add(s);
        Console.WriteLine($"Squarings for the year ({i})= {s}");
        // apply Moore's Law to get number of squarings to do the next year
        int growth = 12204;               // ~x13 up to 2012, at constant rate
        if (i > 2012) growth = 10750;     // ~x5  up to 2034, at constant rate
        s = s.Multiply(new BigInteger(growth.ToString(), 10)).Divide(new BigInteger("10000", 10));
        //Console.WriteLine($"Squarings in year ({i})= {t}");
      }
      Console.WriteLine("Squarings (total)= " + t);
      Console.WriteLine("Ratio of total to first year = " + t.Divide(squaringsFirstYear));
      Console.WriteLine("Ratio of last year to first year = " + s.Divide(squaringsFirstYear.Multiply(new BigInteger("10758", 10)).Divide(new BigInteger("10000", 10))));

      //t = BigInteger.One << 56;
      //Console.WriteLine("Squarings (total)= " + t); //versione 2019

      // Now generate RSA parameters    
      int primelength = 1024;
      Console.WriteLine("Using " + primelength + "-bit primes.");
      BigInteger twoPower = BigInteger.One.ShiftLeft(primelength);

      String pseed = getString("large random integer for prime p seed");
      var prand = new BigInteger(pseed, 10);
      String qseed = getString("large random integer for prime q seed");
      var qrand = new BigInteger(qseed, 10);
      Console.WriteLine("Computing...");

      var p = BigInteger.Five;
      // Note that 5 has maximal order modulo 2^k (See Knuth)
      p = p.ModPow(prand, twoPower).NextProbablePrime();
      Console.WriteLine("p = " + p);

      var q = BigInteger.Five;
      q = q.ModPow(qrand, twoPower).NextProbablePrime();
      Console.WriteLine("q = " + q);

      BigInteger n = p.Multiply(q);
      Console.WriteLine("n = " + n);

      BigInteger pm1 = p.Subtract(ONE);
      BigInteger qm1 = q.Subtract(ONE);
      BigInteger phi = pm1.Multiply(qm1);
      Console.WriteLine("phi = " + phi);

      // Now generate final puzzle value w
      BigInteger u = TWO.ModPow(t, phi);
      BigInteger w = TWO.ModPow(u, n);
      Console.WriteLine("w (hex) = " + w.ToString());

      // Obtain and encrypt the secret message
      // Include seed for p as a check
      StringBuilder sgen = new StringBuilder(getString("string for secret"));
      sgen = sgen.Append(" (seed value b for p = " + prand.ToString() + ")");
      Console.WriteLine("Puzzle secret = " + sgen);
      BigInteger secret = getBigIntegerFromStringBuffer(sgen);
      if (secret.CompareTo(n) > 0)
      { Console.WriteLine("Secret too large!"); return; }
      BigInteger z = secret.Xor(w);  // ^ è lo XOR
      Console.WriteLine("z(hex) = " + z.ToString());

      // Write output to a file
      using (var pw = new StreamWriter(AppDomain.CurrentDomain.BaseDirectory + "puzzleoutput.txt"))
      {
        pw.WriteLine("Crypto-Puzzle for LCS35 Time Capsule.");
        pw.WriteLine("Created by Ronald L. Rivest. April 2, 1999."); pw.WriteLine();
        pw.WriteLine("Puzzle parameters (all in decimal):"); pw.WriteLine();
        pw.Write("n = "); printBigInteger(n, pw); pw.WriteLine();
        pw.Write("t = "); printBigInteger(t, pw); pw.WriteLine();
        pw.Write("z = "); printBigInteger(z, pw); pw.WriteLine();
        pw.WriteLine("To solve the puzzle, first compute w = 2^(2^t) (mod n).");
        pw.WriteLine("Then exclusive-or the result with z.");
        pw.WriteLine("(Right-justify the two strings first.)");
        pw.WriteLine();
        pw.WriteLine("The result is the secret message (8 bits per character),");
        pw.WriteLine("including information that will allow you to factor n.");
        pw.WriteLine("(The extra information is a seed value b, such that ");
        pw.WriteLine("5^b (mod 2^1024) is just below a prime factor of n.)");
        pw.WriteLine(" ");
      }

      // Wait for input carriage return to pause before closing
      Console.Read();
    }

    static BigInteger ONE = BigInteger.One;
    static BigInteger TWO = BigInteger.Two;

    static String getString(String what)
    {
      // This routine is essentially a prompted "readLine"
      StringBuilder s = new StringBuilder();
      Console.WriteLine("Enter " + what + " followed by a carriage return:");
      for (int i = 0; i < 1000; i++)
      {
        int c = Console.Read();
        if (c < 0 || c == '\n') break;
        if (c != '\r') // note: ignore cr before newline
          s = s.Append((char)c);
      }
      return (s.ToString());
    }

    static BigInteger getBigIntegerFromStringBuffer(StringBuilder s)
    {
      // Base-256 interpretation of the given string
      var randbi = BigInteger.Zero;
      for (int i = 0; i < s.Length; i++)
      {
        int c = s[i]; //s.charAt(i);
        randbi = randbi.ShiftLeft(8).Add(new BigInteger(c.ToString(), 10));
      }
      Console.WriteLine("Value of string entered (hex) = " + randbi.ToString());
      return randbi;
    }

    static void printBigInteger(BigInteger x, StreamWriter pw)
    {
      String s = x.ToString();
      int charsPerLine = 60;
      for (int i = 0; i < s.Length; i += charsPerLine)
      {
        if (i != 0) { pw.WriteLine(); pw.Write("    "); }
        pw.Write(s.Substring(i, Math.Min(charsPerLine, s.Length - i)));
        //pw.Write(s.Substring(i, Math.Min(i + charsPerLine, s.Length)));
      }
      pw.WriteLine();
    }

    /*
    static BigInteger getNextPrime(BigInteger startvalue)
    {
      BigInteger p = startvalue;
      if (!p.and(ONE).equals(ONE)) p = p.add(ONE);
      while (!p.isProbablePrime(40)) p = p.add(TWO);
      return (p);
    }*/



  }
}
