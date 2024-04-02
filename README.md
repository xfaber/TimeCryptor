## TimeCryptor

Progetto che implementa una serie di prove di concetto (Proof Of Concept) di protocolli Time Lock Encryption.

## PoC del protocollo TLCS 

### Classe statica :

```plaintext
PoC_TlcsMuon_i
```

Implementazione del protocollo TLE con l'approccio dei Time Lock Puzzle.

Il prototipo permette di creare un puzzle e risolverlo.  
Per la cifratura/decifratura è stato utilizzato lo schema di cifratura RC5 con una chiave a 160 bit.

### Parametri locali PoC

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

## PoC del protocollo ![](https://github.com/xfaber/TimeCryptor/blob/master/images/muon_i.svg) 

Implementa ll protocollo TLCS “muon” in versione interattiva

### Classe statica :

```plaintext
PoC_TlcsMuon_i
```

### Elenco dei parametri da impostare per l'esecuzione della prova:

#### Parametri locali PoC

```plaintext
  var MUON_VerifyMode = VerifyModeEnum.Interactive;
  var LOE_ReqDataMode = LeagueOfEntropy.ReqDataModeEnum.FromLocal;
  var message = "Hello TLE!";
  var futureDateTime = DateTime.Now.AddSeconds(10);
```

#### Parametri globali PoC

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

## PoC del protocollo ![](https://github.com/xfaber/TimeCryptor/blob/master/images/muon_ni.svg)

Implementa ll protocollo TLCS “muon” in versione non interattiva

### Classe statica :

```plaintext
PoC_TlcsMuon_ni
```

### Elenco dei parametri da impostare per l'esecuzione della prova:

#### Parametri locali PoC

```plaintext
  var MUON_VerifyMode = VerifyModeEnum.NotInteractive;
  var LOE_ReqDataMode = LeagueOfEntropy.ReqDataModeEnum.FromLocal;
  var message = "Hello TLE!";
  var futureDateTime = DateTime.Now.AddSeconds(10);
```

#### Parametri globali PoC

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

## Modalità di richiesta dei dati LOE

Enumerativo `ReqDataModeEnum`

*   `FromWeb`: permette di recuperare la chiave dal servizio HTTP API drand per la rete specificata da `drandNetworkHash`, con il metodo `GetPkFromWeb()`.
*   `FromLocal`: permette di recuperare chiave e firme LOE, creandole in locale in modo casuale, attraverso una apposita procedura implementata nel metodo `Set_LOE_Data_FromLocal()`.

## Simulazione contributore non valido

Impostando il parametro `bHonestParty=false` nella chiamata al metodo `PublishToBlockchain` della classe `Contributors` viene simulato il comportamento di un contributore malevolo, che invia dati errati sulla blockchain. In questo modo viene pubblicata dallo specifico contributore una chiave casuale non coerente.
