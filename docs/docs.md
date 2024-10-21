# Sequentie diagrammen

## Burger log in bij PGO

```mermaid
sequenceDiagram
	actor burger as Karel<br>(PGO gerbuiker)
	participant PGO1
	participant VAD
	participant PRS

	autonumber

	burger ->> PGO1: Klik op "inloggen"
	PGO1 ->> VAD: Verzoek authenticatie<br> voor PGO
	VAD -->> burger: Login prompt

	burger ->> VAD: Log in
	note over VAD: verkrijg BSN
	VAD ->> PRS: Activate BSN
	PRS -->> VAD: polymorf Pseudoniem<br> [PP@VAD]
	VAD -->> PGO1: Sessie



	PGO1 ->> VAD: Geef pseudoniem voor PGO1<br> [PGO1, Sessie, PGO1 public key]
	note over VAD: Maak Encrypted Pseudoniem voor PGO1
	VAD ->> PGO1: EP@PGO1

	note over PGO1: pseudoniem ontsleutelen [EP@HA]
```

## PGO vraagt op bij Zorgaanbieder

```mermaid

sequenceDiagram
    participant PGO1
    participant PRS
    participant HA as Huisarts
    participant TSR as Toestemmingen<br> register

    autonumber

    PGO1 ->> VAD: Geef pseudoniem voor Huisarts<br> [HA-ID, Sessie]
    VAD ->> Adressering: Haal huidige versie &<br> public key op voor HA<br>[HA-ID]
    Adressering->>VAD: Public key HA
    note over VAD: Maak Encrypted Pseudoniem voor HA
    VAD ->> PGO1: EP@HA

    PGO1 ->> HA: Vraag Karel's medische gegevens<br> [EP@HA]
    note over HA: Decrypt EP@HA -> pseudoniem
    HA->>Adressering: Lookup public key [TSR-ID]
    Adressering->>HA: Public key en versie
    note over HA: Lookup naar polymorf pseudoniem<br>en maak PP@HA -> EP@TSR
    HA ->> TSR: Is er toestemming voor leveren<br> van gegevens aan PGO?<br> [EP@TSR, HA, PGO]
    note over TSR: Decrypt EP@TSR -> P@TSR, Zoek toestemming<br> [P@TSR, doel=PGO, bron=HA]
    TSR -->> HA: Ja
    note over HA: Verzamel medische gegevens
    HA -->> PGO1: Medische gegege
```

## Zorgaanbieder lokaliseert gegevens

```mermaid
sequenceDiagram
    participant HA as Huisarts<br/> (HA)
    participant PRS as PRS
    participant NVI as LokalisatieRegister<br> (NVI)
    participant TSR as Toestemmingen<br/>register<br/>(TSR)

    autonumber

    HA ->> PRS: Activeer (BSN)
    PRS -->> HA: PolymorfPseudoniem [PP@HA]


    note over HA: Maak pseudoniem voor <br/>NVI + Toestemmingsregister<br/>[PP@HA, NVI]
    HA ->> NVI: Vraag Karel's zorgaanbieder-lijst<br/> [EP@NVI, EP@TSR]
    NVI ->> TSR: Haal toestemming op<br> [EP@TSR, NVI, Huisarts]
    note over TSR: Decrypt EP@TSR -> Ps@TSR <br> Zoek toestemmingen voor<br> [Ps@TSR, doel=NVI, bron=HA]
    TSR -->> NVI: Toestemmingen
    note over NVI: Decrypt EP@NVI -> Ps@NVI<br> Zoek zorgaanbieders<br> [Ps@NVI, doel=HA]
    NVI -->> HA: [Apotheek1, Huisarts1, Ziekenhuis1]
```




### Migratie 



Migratie van pseudoniemen van één partij

```mermaid
sequenceDiagram
autonumber

note over PGO1: Pas versie nummer aan en maak nieuwe keys

loop Voor alle geregistreerde pseudoniemen
PGO1 ->> vad: Vraag om pseudoniem [Sessie,nieuwe key]
note over VAD: Maak Encrypted Pseudoniem voor PGO1
VAD ->> PGO1: EP@PGO1

note over PGO1: Registreer nieuwe pseudoniem
end
```

Partij met PP

```mermaid
sequenceDiagram
autonumber

note over HA: Pas versie nummer aan en maak nieuwe keys
HA->>Adressering: Registreer nieuwe versie en publieke sleutel

loop Voor alle geregistreerde BSN
note over HA: Maak Encrypted Pseudoniem voor HA
note over HA: Decrypt Pseudoniem voor HA
note over HA: Registreer nieuwe pseudoniem
note over HA: Registreer relatie oude & nieuwe pseudoniem

end

oud->>HA: Vraag op via oud pseudoniem [Pv1]
note over HA: Zie dat het een oude versie betreft, decrypt en zoek in koppeltabel

```

Migratie van alle pseudoniemen

```mermaid
sequenceDiagram
autonumber

note over PAS: Pas activatie versie & sleutel aan

HA->>PAS: Verifieer activatie versie
PAS->>HA: Geef actuele versie [v2]
note over HA: Zie dat versie anders is en start migratie

nieuw->>HA: Vraag op basis van activatie V2
alt Migratie al gedaan
note over HA: Verwerk als normaal
else Migratie nog niet gedaan
HA->>nieuwe: Verzoek om oude versie te gebruiken
nieuwe->>PAS: activeer met V1<br>(dit mag enkel tijdelijk)
PAS->>nieuwe: oude activatie
nieuwe->>HA: V1 versie
end

```

Crypto rollover


```mermaid
sequenceDiagram
autonumber

note over PAS: Nieuwe versie algoritmes...

```