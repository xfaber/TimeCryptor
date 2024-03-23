using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TimeCryptor.Utils;

namespace TimeCryptor
{
  public static class PoC_TLP
  {
    public static void Run_PoC()
    {
      // 11/11/2023 --> Impostantdo una lunghezza in bit dei numeri primi scelti a 4096 il tempo di creazione del puzzle supera il tempo di risoluzione
      var bitLengthPrimeNum = 1024;                               // lunghezza in bit dei numeri primi scelti    

      // numero di quadrature al secondo del risolutore (che decifra il messagio)
      var numQuadrature = new Org.BouncyCastle.Math.BigInteger("300000");
      var quadratureParams = GetSquarePerSecond(numQuadrature, bitLengthPrimeNum);
      //  45454 con 2048 bit                           
      // 200000 con 1024 bit

      var messaggio = "Ciao Ali";                                 // messaggio da cifrare

      //var futureDate = new DateTime(2023, 12, 10, 00, 00, 00);  
      //var tempo = int.Parse(Math.Truncate((futureDate - DateTime.Now).TotalSeconds).ToString());

      var tempo = 10; // 1*24*60*60;                              // tempo in secondi (tempo desiderato necessario alla decifratura)   
      var bitLengthKey = 160;                                     // lunghezza in bit della chiave per la cifratura (256 bit per AES e 160 per RC5)
      var keyString = CryptoUtils.GetRandomKey(bitLengthKey / 8); // genera una chiave casuale    

      Logger.Log($"Messaggio: {messaggio}");
      Logger.Log($"Chiave: {keyString}");
      Logger.Log($"Lunghezza chiave (bit): {bitLengthKey}");
      Logger.Log($"Lunghezza numeri primi (bit): {bitLengthPrimeNum}");
      Logger.Log($"Tempo previsto per la risoluzione (secondi): {tempo}");
      Logger.Log($"Potenza di calcolo del risolutore (quadrature/secondo): {quadratureParams.quadratureAlSec}\n");

      Console.WriteLine($"---------------------------------------------------------------------------");
      Logger.Log($"Creazione time lock puzzle -INIZIO-");
      Stopwatch sw = new Stopwatch();
      sw.Start();
      var puzzleParameters = CreateTLP(messaggio, keyString, tempo, quadratureParams.p, quadratureParams.q, quadratureParams.a, quadratureParams.quadratureAlSec, bitLengthPrimeNum);
      sw.Stop();
      //Logger.Log($"Tempo per la creazione del puzzle: {sw.ElapsedMilliseconds} ms");
      Logger.Log($"n: -- prodotto dei due numeri primi p e q --"); puzzleParameters.n.Print();
      Logger.Log($"a: {puzzleParameters.a} -- numero casuale scelto nell’intervallo ]1,n[ --", false); //puzzleParameters.a.Print();
                                                                                                       //Logger.Log($"a<n: {puzzleParameters.a.CompareTo(puzzleParameters.n)}");
      var na = System.Numerics.BigInteger.Parse(puzzleParameters.a.ToString());
      var nn = System.Numerics.BigInteger.Parse(puzzleParameters.n.ToString());
      //Logger.Log($"a<n: {((na < nn) ? "TRUE" : "FALSE!")}");
      Logger.Log($"t: {puzzleParameters.t} -- quadrature totli da computare per la risoluzione --");
      Logger.Log($"CK: -- chiave K cifrata CK=K+b mod n --"); puzzleParameters.CK.Print();
      Logger.Log($"CM: {puzzleParameters.CM} -- messaggio M cifrato con schema RC5 e chiave K --");
      Logger.Log($"Creazione time lock puzzle -FINE-");
      Console.WriteLine($"---------------------------------------------------------------------------");
      Logger.Log($"Tempo per la creazione del puzzle: {sw.ElapsedMilliseconds} ms ({sw.ElapsedMilliseconds / 1000} s)\n");


      var bRisolvi = true;
      if (bRisolvi)
      {
        Console.WriteLine($"---------------------------------------------------------------------------");
        Logger.Log($"Risoluzione time lock puzzle -INIZIO-");
        sw.Restart();
        var ret = ResolveTLP(puzzleParameters);
        sw.Stop();
        Logger.Log($"decryptedKey = keyString ? {((ret.decryptedKey == keyString) ? "OK" : ".......ERRORE!")}");
        Logger.Log($"decryptedMessage = messaggio ? {((ret.decryptedMessage == messaggio) ? "OK" : ".......ERRORE!")}");
        Logger.Log($"Risoluzione time lock puzzle -FINE-");
        Console.WriteLine($"---------------------------------------------------------------------------");
        Logger.Log($"Tempo per la risoluzione del puzzle: {sw.ElapsedMilliseconds} ms ({sw.ElapsedMilliseconds / 1000} s)");
      }
    }

    /// <summary>
    /// Restituisce la tupla (n,a,t,CK,CM) con i componenti del puzzle da risolvere per decifrare il messaggio
    /// </summary>
    /// <param name="messaggio">il messaggio da cifrare (si usa la cifratura RC5 con un solo blocco di 8 byte = 64 bit)</param>
    /// <param name="tempo">Tempo che deve durare il massaggio</param>
    /// <param name="quadratureAlSec">
    /// Numero di quadrature al secondo del resolver (chi decifra)
    /// Valore precedentemente stimato attraverso il metodo GetSquarePerSecond()
    /// </param>
    /// <param name="p">
    /// numero primo casuale 
    /// </param>
    /// <param name="q">
    /// numero primo casuale 
    /// </param>
    /// <param name="a">
    /// numero casuale tale che (1 < a < n)
    /// </param>
    /// <returns></returns>
    public static (Org.BouncyCastle.Math.BigInteger n, 
                   Org.BouncyCastle.Math.BigInteger a, 
                   Org.BouncyCastle.Math.BigInteger t, 
                   Org.BouncyCastle.Math.BigInteger CK, string CM) 
      CreateTLP(string messaggio, string keyString, int tempo, Org.BouncyCastle.Math.BigInteger p, Org.BouncyCastle.Math.BigInteger q, Org.BouncyCastle.Math.BigInteger a, Org.BouncyCastle.Math.BigInteger quadratureAlSec, int bitLengthPrimeNum = 1024)
    {
      // Supponiamo che Alice abbia un messaggio M
      // che vuole crittografare con un puzzle time-lock 
      // per un periodo di tempo di T secondi.
      var M = messaggio;                                // Il messaggio da cifrare
      var T = CryptoUtils.ConvertToBigIntergerBC(tempo);            // Il tempo in secondi  (che deve essere impiegato per la decifratura)
      var S = quadratureAlSec;  // S è il numero di quadrature modulo n al secondo che possono essere elaborate dal risolutore

      // Genera il modulo composito n come prodotto di due grandi numeri primi segreti p e q scelti casualmente
      var n = p.Multiply(q);
      Logger.Log($"p: -- numero primo scelto casualmente --"); p.Print();
      Logger.Log($"q: -- numero primo scelto casualmente --"); q.Print();
      //Logger.Log($"n: {n.ToString()}");

      //Calcola anche phi(n) = (p - 1) * (q - 1)
      var phi_di_n = (p.Subtract(Org.BouncyCastle.Math.BigInteger.One)).Multiply(q.Subtract(Org.BouncyCastle.Math.BigInteger.One));
      Logger.Log($"phi_di_n: -- toziente di Eulero = (p-1)(q-1) --"); phi_di_n.Print();

      // Calcola il numero di quadrature necessarie alla risoluzione in tempo T 
      Org.BouncyCastle.Math.BigInteger t = T.Multiply(S);
      Logger.Log($"Quadrature totali per la risoluzione - t:{t}");

      var K = new Org.BouncyCastle.Math.BigInteger(Encoding.UTF8.GetBytes(keyString));
      //Logger.Log($"Original message {M}");
      //Cifra M con chiave K usando un algoritmo di crittografia (ad esempio RC5) per ottenere il testo cifrato
      var CM = CryptoUtils.Rc5_Encrypt(keyString, M);
      //var CM = CryptoUtils.AES_Encrypt(keyString, M);

      // Cifra la chiave K calcolando CK = K + a^(2^t) (mod n)   
      // Per farlo in modo efficiente, prima calcola e=2^t (mod ϕ(n))
      var e = Org.BouncyCastle.Math.BigInteger.Two.ModPow(t, phi_di_n);
      Logger.Log($"e: -- =2^t mod (phi_di_n) - parametro trapdoor il calcolo efficiente di CK --"); e.Print();

      // poi calcola b = a^e (mod n)	
      var b = a.ModPow(e, n);
      Logger.Log($"b: -- =a^e mod (n) - parametro trapdoor il calcolo efficiente di CK --"); b.Print();

      // Produce come output il puzzle time-lock (n, a, t, CK, CM) e cancella tutte le altre variabili (p, q) create durante questo calcolo.
      var CK = K.Add(b);

      return (n, a, t, CK, CM); //public params
    }

    /// <summary>
    /// Risolve il puzzle restituendo la tupla (K,M) chiave e messaggio decifrati
    /// </summary>
    /// <param name="publicParams"></param>
    /// <returns></returns>
    public static (string decryptedKey, string decryptedMessage) 
      ResolveTLP((Org.BouncyCastle.Math.BigInteger n, Org.BouncyCastle.Math.BigInteger a, Org.BouncyCastle.Math.BigInteger t, Org.BouncyCastle.Math.BigInteger CK, string CM) publicParams)
    {
      // n = p*q
      // a = numero casuale 1<a<n
      // t = T(tempo necessario per la decifratura) * S (numero di quadrature al secondo della macchina resolver)

      // Il tempo per decifrare il messaggio inizia da quando comincia la computazione per decifrarlo (tempo elaborazione necessario alla macchina per terminare la decifratura)
      // Ipotizziamo che Alice manda un messaggio a Bob (impostando T = 1 giorno ==> serve un giorno per calcolare la decifratura)
      // Se la macchina di Bob inizia a computare la decifratura dopo due giorni, c'e ne vorranno alla fine 3 (2 per poter iniziare a decifrare e 1 per poter finire) per leggere il messaggio.
      // Se Evil intercetta il messaggio e comincia a decifrarlo prima che Bob possa farlo, riuscirà a leggerlo prima di lui.

      //In base alla progettazione, la ricerca diretta della chiave K di RC5 non è fattibile, quindi l'approccio più veloce conosciuto per risolvere il puzzle è determinare
      //b = a^(2^t) mod n = (a^2 * a^2 * … * a^2) (t volte) mod n
      //CK = K + a^2^t mod n ==> K = CK - a^2^t mod n ==> K = CK - b

      Stopwatch sw = new Stopwatch();
      sw.Start();

      // METODO 1
      //Org.BouncyCastle.Math.BigInteger aexp;
      //try
      //{
      //  // Calcola 2^t (per t intero) 
      //  //throw new Exception();
      //  aexp = Org.BouncyCastle.Math.BigInteger.Two.Pow(publicParams.t.IntValueExact);
      //}
      //catch (Exception)
      //{
      //  // Calcola 2^t (per t BigInteger)
      //  if (publicParams.t.Equals(Org.BouncyCastle.Math.BigInteger.Zero)) aexp = Org.BouncyCastle.Math.BigInteger.One;
      //  else if (publicParams.t.Equals(Org.BouncyCastle.Math.BigInteger.One)) aexp = Org.BouncyCastle.Math.BigInteger.Two;
      //  else
      //  {
      //    aexp = Org.BouncyCastle.Math.BigInteger.Two;
      //    for (var i = Org.BouncyCastle.Math.BigInteger.One; i.CompareTo(publicParams.t) < 0; i = i.Add(Org.BouncyCastle.Math.BigInteger.One))
      //    {
      //      aexp = Org.BouncyCastle.Math.BigInteger.Two.Multiply(aexp);
      //    }
      //  }
      //}
      //sw.Stop();
      //Logger.Log($"Tempo elaborazione 2^t del puzzle: {sw.ElapsedMilliseconds} ms");
      //sw.Restart();
      //var b = publicParams.a.ModPow(aexp, publicParams.n);                  // Calcola a^(2^t) mod n


      //METODO 2
      var b = publicParams.a.ModPow(Org.BouncyCastle.Math.BigInteger.Two.Pow(publicParams.t.IntValue), publicParams.n);
      //var b2 = publicParams.a.ModPow(Org.BouncyCastle.Math.BigInteger.Two.ModPow(publicParams.t, publicParams.n), publicParams.n);
      //var b = publicParams.a.Mod(publicParams.n);
      //for (Org.BouncyCastle.Math.BigInteger i = Org.BouncyCastle.Math.BigInteger.One; i.CompareTo(publicParams.t)<1; i.Add(Org.BouncyCastle.Math.BigInteger.One))
      // {
      //  b = b.ModPow(Org.BouncyCastle.Math.BigInteger.Two, publicParams.n);
      // }
      sw.Stop();
      //Logger.Log($"b: "); b.Print();
      Logger.Log($"Tempo elaborazione quadrature del puzzle: {sw.ElapsedMilliseconds} ms");

      //var b = publicParams.a.Pow(2).Pow(publicParams.t).Mod(publicParams.n);
      var K = publicParams.CK.Subtract(b).Mod(publicParams.n);                                  // Calcola K = CK - b

      var decryptedKey = Encoding.UTF8.GetString(K.ToByteArray());
      var decryptedMessage = CryptoUtils.Rc5_Decrypt(decryptedKey, publicParams.CM);
      //var decryptedMessage = CryptoUtils.AES_Decrypt(decryptedKey, publicParams.CM);

      Logger.Log($"decryptedKey: {decryptedKey}");
      Logger.Log($"Messaggio decifrato: {decryptedMessage}");
      return (decryptedKey, decryptedMessage);
    }

    public static (Org.BouncyCastle.Math.BigInteger p, 
      Org.BouncyCastle.Math.BigInteger q, 
      Org.BouncyCastle.Math.BigInteger a, 
      Org.BouncyCastle.Math.BigInteger quadratureAlSec) 
      GetSquarePerSecond(Org.BouncyCastle.Math.BigInteger numeroQuadrature, int bitLengthPrimeNum)
    {
      var p = CryptoUtils.GetRandomPrimeNumber(bitLengthPrimeNum);
      var q = CryptoUtils.GetRandomPrimeNumber(bitLengthPrimeNum);
      var n = p.Multiply(q);
      var a = Org.BouncyCastle.Math.BigInteger.Two; // GetSecureRandomNumberFromBC(Org.BouncyCastle.Math.BigInteger.One, n);

      //Logger.Log($"p: "); p.Print();
      //Logger.Log($"q: "); q.Print();
      //Logger.Log($"n: "); n.Print();
      //Logger.Log($"a: ",false);a.Print();
      Console.WriteLine("");
      Console.WriteLine($"---------------------------------------------------------------------------");
      Logger.Log($"Calcolo {numeroQuadrature} quadrature di a modulo n");

      // Calcola a^2^t mod n
      // METODO 2 ---> ...in alcuni casi è piu veloce di quello sopra
      var mille = new Org.BouncyCastle.Math.BigInteger("1000");
      var sw = new Stopwatch();
      sw.Start();
      var b = a.ModPow(Org.BouncyCastle.Math.BigInteger.Two.Pow(numeroQuadrature.IntValue), n);
      sw.Stop();
      Logger.Log($"Tempo di elaborazione per {numeroQuadrature} quadrature: {sw.Elapsed.TotalMilliseconds} ms");
      var ms = new Org.BouncyCastle.Math.BigInteger(Math.Ceiling(sw.Elapsed.TotalMilliseconds).ToString());
      var quadraturePerSecond = numeroQuadrature.Divide(ms).Multiply(mille);
      Console.WriteLine($"---------------------------------------------------------------------------");
      Logger.Log($"Numero quadrature per secondo per questa macchina: {quadraturePerSecond}");

      //Logger.Log($"b: "); b.Print();

      return (p, q, a, quadraturePerSecond);
    }
  }
}
