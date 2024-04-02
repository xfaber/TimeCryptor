## TimeCryptor

Progetto che implementa una serie di prove di concetto (Proof Of Concept) di protocolli Time Lock Encryption.

Le prove di concetto sono finalizzate alla verifica della corretta funzionalità dei protocolli 
e permettono di avere un approccio pratico su come affrontare le diverse problematiche che si possono incontrare durante l'implementazione di questi protocolli.

=======================================================

La solution Visual Studio contiene una applicazione console.
Attraverso il metodo Main della classe Program è possibile richiamare l’esecuzione di ognuna delle PoC sviluppate. 
Ogni prototipo è stato racchiuso in una classe statica denominata con il prefisso “PoC_[nome protocollo] “:

•	PoC_TLP.cs
•	PoC_TlcsMuon_i.cs
•	PoC_TlcsMuon_ni.cs

Ciascuna di queste classi statiche espone il metodo Run_PoC(), che lancia l’esecuzione della prova di concetto per lo specifico protocollo implementato.

L’esecuzione delle PoC non prevede alcuna interazione con l’utente, che le esegue.
Durante l’esecuzione vengono visualizzati una serie di messaggi, che permettono di seguire i passi di elaborazione dei vari blocchi che rappresentano le diverse fasi dello schema. 
I parametri (locali/globali) necessari all'esecuzione, vengono impostati automaticamente nel codice durante i vari passaggi. 

Questi parametri possono facilmente essere modificati nel sorgente, utilizzando le apposite proprietà delle classi per creare altri casi di test.

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

Il caso di test implementato nella prova di concetto esegue la generazione di una coppia di chiavi (MPK_R, sk_R) 
che sono in seguito utilizzate per la cifrare/decifrare un messaggio di prova. 
Viene simulato anche l’invio di dati non corretti da parte di uno dei contributori. 

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
Il caso di test delal prove di concetto è il medesimo della versioen interattiva. 
Esegue la generazione di una coppia di chiavi (MPK_R, sk_R) 
che sono in seguito utilizzate per la cifrare/decifrare un messaggio di prova. 
Viene simulato anche l’invio di dati non corretti da parte di uno dei contributori.
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