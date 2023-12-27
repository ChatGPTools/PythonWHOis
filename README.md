# Scansione IP e Porte - Script Python

Questo script Python offre un'applicazione che combina la scansione degli indirizzi IP nella rete con la possibilità di ottenere informazioni di base, informazioni sulla posizione, informazioni WHOIS e una scansione delle porte aperte di un dispositivo specifico.

## Requisiti

- Python 3.x installato sul sistema
- Librerie Python richieste:
  ```bash
  pip install requests ipwhois scapy

## Utilizzo
**Esegui lo script:**
```bash
python script.py
```

**Segui le istruzioni a schermo:**

Inserisci l'indirizzo IP da cui iniziare la scansione.

Inserisci la subnet mask (es. 255.255.255.0).

Seleziona un dispositivo specifico per la scansione delle porte.

Scegli tra le opzioni disponibili per ottenere informazioni specifiche.

## Opzioni

**Informazioni di base sull'IP**

Ottieni l'hostname e l'indirizzo IP associato.


**Informazioni sulla posizione dell'IP**

Ottieni informazioni sulla posizione utilizzando un servizio di geolocalizzazione.


**Informazioni WHOIS sull'IP**

Ottieni informazioni WHOIS sull'indirizzo IP.


**Tutte le informazioni**

Ottieni tutte le informazioni di base, informazioni sulla posizione e informazioni WHOIS.


**Scansione delle porte**
Effettua una scansione delle porte aperte di un dispositivo specifico.


## Note
Assicurati di avere le autorizzazioni necessarie per eseguire la scansione nella tua rete.
