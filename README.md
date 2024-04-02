## TimeCryptor

Progetto che implementa una serie di prove di concetto (Proof Of Concept) di protocolli Time Lock Encryption.

Le prove di concetto sono finalizzate alla verifica della corretta funzionalità dei protocolli  
e permettono di avere un approccio pratico su come affrontare le diverse problematiche che si possono incontrare durante l'implementazione di questi protocolli.

\=======================================================

La solution Visual Studio contiene una applicazione console.  
Attraverso il metodo Main della classe Program è possibile richiamare l’esecuzione di ognuna delle PoC sviluppate.  
Ogni prototipo è stato racchiuso in una classe statica denominata con il prefisso “PoC\_"+\[nome protocollo\] nomenclatura utilizzata anche per il rispettivo file .cs.

*   `PoC_TLP`
*   `PoC_TlcsMuon_i`
*   `PoC_TlcsMuon_ni`

Ciascuna di queste classi espone il metodo Run\_PoC(), per lanciare l’esecuzione della prova di concetto dello specifico protocollo implementato.

L’esecuzione delle PoC non prevede alcuna interazione con l’utente, che la esegue.  
Durante l'elaborazione vengono visualizzati una serie di messaggi, che permettono di seguire i vari blocchi relativi alle diverse fasi dello schema.  
I parametri (locali/globali) necessari all'esecuzione, vengono impostati direttamente nel codice.

Questi parametri possono facilmente essere modificati nel sorgente, mediante le apposite proprietà delle classi al fine di creare altri casi di test.

### PoC del protocollo TLP

Implementazione del protocollo TLE con l'approccio dei Time Lock Puzzle.

Il prototipo permette di creare un puzzle e risolverlo.  
Per la cifratura/decifratura è stato utilizzato lo schema di cifratura RC5 con una chiave a 160 bit.

#### Classe statica `PoC_TLP`

#### Parametri locali PoC

```plaintext
var messaggio = "Ciao TLP";                                  // messaggio da cifrare
var tempo = 10;                                              // tempo di blocco in secondi (tempo desiderato necessario alla decifratura)   
var bitLengthKey = 160;                                      // lunghezza in bit chiave di cifratura (256 bit per AES e 160 per RC5)
var keyString = CryptoUtils.GetRandomKey(bitLengthKey / 8);  // chiave di cifratura casuale    
```

Per lanciare l'esecuzione della PoC chiamare il metodo `Run_PoC()`

```plaintext
PoC_TLP.Run_PoC()
```

### PoC del protocollo ![](https://github.com/xfaber/TimeCryptor/blob/master/images/muon_i.svg)

Implementa ll protocollo TLCS “muon” in versione interattiva

Il caso di test implementato nella prova di concetto esegue la cifratura a blocco temporale di un messaggio di prova con un blocco di 10 a partire dalla data/ora corrente (dell'esecuzione).  
Viene simulata la pubblicazione di dati non corretti sulla blockchain da parte di uno dei contributori.

I blocchi che implementano il test ed eseguono le varie fasi del protocollo sono i seguneti:

1.  Configurazioni generali
2.  Impostazione parametri PoC
3.  Creazione istanze delle classi specifiche
4.  Generazione dei parametri pubblici e pubblicazione sulla blockchain
5.  Verifica delle prove 
6.  Aggregazione (calcolo della chiave pubblica master MPK\_R)
7.  Cifratura 
8.  Recupero della firma LOE
9.  Procedura di inversione  (calcolo della chiave segreta sk\_r)
10.  Decifratura 
    

#### Classe statica  `PoC_TlcsMuon_i`

#### Elenco dei parametri da impostare per l'esecuzione della prova:

##### Parametri locali PoC

```plaintext
  var MUON_VerifyMode = VerifyModeEnum.Interactive;
  var LOE_ReqDataMode = LeagueOfEntropy.ReqDataModeEnum.FromLocal;
  var message = "Hello TLE!";
  var futureDateTime = DateTime.Now.AddSeconds(10);
```

##### Parametri globali PoC

```plaintext
  _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
  _globalParams.k = 3; //parametro di sicurezza per errore di solidità
  _globalParams.numeroContributori = 3;
  _globalParams.PKLOE = _LOE.pk;
```

Per lanciare l'esecuzione della PoC chiamare il metodo `Run_PoC()`

```plaintext
PoC_TlcsMuon_i.Run_PoC()
```

### PoC del protocollo ![](https://github.com/xfaber/TimeCryptor/blob/master/images/muon_ni.svg)

Implementa ll protocollo TLCS “muon” in versione non interattiva.  
Il caso di test della prova di concetto è il medesimo della versione interattiva.  
Il test esegue la generazione di una coppia di chiavi (MPK\_R, sk\_R)  
che in seguito vengono utilizzate per cifrare/decifrare un messaggio di prova.  
Viene simulato l’invio di dati non corretti da parte di uno dei contributori.

#### Classe statica `PoC_TlcsMuon_ni`

#### Elenco dei parametri da impostare per l'esecuzione della prova:

##### Parametri locali PoC

```plaintext
  var MUON_VerifyMode = VerifyModeEnum.NotInteractive;
  var LOE_ReqDataMode = LeagueOfEntropy.ReqDataModeEnum.FromLocal;
  var message = "Hello TLE!";
  var futureDateTime = DateTime.Now.AddSeconds(10);
```

##### Parametri globali PoC

```plaintext
  _globalParams = new GlobalParams(CryptoUtils.ECname.secp256k1);
  _globalParams.k = 3; //parametro di sicurezza per errore di solidità
  _globalParams.numeroContributori = 3;
  _globalParams.PKLOE = _LOE.pk;
```

Per lanciare l'esecuzione della PoC chiamare il metodo `Run_PoC()`

```plaintext
PoC_TlcsMuon_ni.Run_PoC()
```

### Modalità di richiesta dei dati LOE

Enumerativo `ReqDataModeEnum`

*   `FromWeb`: permette di recuperare la chiave dal servizio HTTP API drand per la rete specificata da `drandNetworkHash`, con il metodo `GetPkFromWeb()`.
*   `FromLocal`: permette di recuperare chiave e firme LOE, creandole in locale in modo casuale, attraverso una apposita procedura implementata nel metodo `Set_LOE_Data_FromLocal()`.

### Simulazione contributore non valido

Impostando il parametro `bHonestParty=false` nella chiamata al metodo `PublishToBlockchain` della classe `Contributors` viene simulato il comportamento di un contributore malevolo, che invia dati errati sulla blockchain. In questo modo viene pubblicata dallo specifico contributore una chiave casuale non coerente.