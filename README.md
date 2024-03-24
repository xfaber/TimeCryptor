# TimeCryptor
Progetto che implementa una serie di Proof of Concept di protocolli per Time Lock Encryption.


## Classe PoC_RSW_Puzzle 
Implementazione del protocollo TLE con l'approccio dei Time Lock Puzzle.

Il prototipo permette di creare un puzzle e risolverlo. 
Per la cifratura/decifratura è stato utilizzato lo schema di cifratura RC5 con una chiave a 160 bit.

Per lanciare l'esecuzione della PoC chiamare il metodo
```
PoC_TLP.Run_PoC()
```

## Classe PoC_TlcsMuon_i
Implementazione del protocollo TLCS Muon in versione interattiva

Per lanciare l'esecuzione della PoC chiamare il metodo
```
PoC_TlcsMuon_i.Run_PoC()
```

## Classe PoC_TlcsMuon_ni
Implementazione del protocollo TLCS Muon in versione non interattiva 

Per lanciare l'esecuzione della PoC chiamare il metodo
```
PoC_TlcsMuon_ni.Run_PoC()
```