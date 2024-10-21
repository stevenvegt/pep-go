# Sequentie diagrammen

Algemene patroon BSN partij


```mermaid
sequenceDiagram
    participant X
    participant PAS
    participant KL as Key-Lookup<br>DNS/Adressering/...

    autonumber

    note over X: Activatie
    X ->> X: Maak public & private key
    X ->> PAS: Activeer BSN<br>[BSN, public key]
    PAS ->> X: Versleuteld PP

    note over X: Pseudoniem voor eigen gebruik
    X ->> X: Maak versleuteld pseudoniem<br>[VPP,public key]
    X ->> X: Decrypt VP@X

    note over X: Interactie met andere partij
    X ->> KL: Haal key op<br>[Y-ID]
    KL ->> X: Public key voor Y
    X ->> X: Maak versleuteld pseudoniem<br>[VPP,PK@Y]
    X ->> Y: Stel vraag<br>[VP@Y]
    Y ->> Y: Ontsleutel<br>[VP@Y]
```

Algemeen niet BSN gerechtigd

```mermaid
sequenceDiagram
	autonumber

    participant A
    participant VAD
    participant PAS
    participant KL as Key-Lookup<br>DNS/Adressering/...

    note over A: Verkrijg sessie key
    A->>VAD: Authenticeer
    note over VAD: Verkrijg BSN via WDO middel
    VAD->>PAS: Activeer<br>[BSN]
    PAS->>VAD: VPP
    VAD->>A: Sessie

    note over A: Verkrijg pseudoniem
    A->>VAD: Vraag pseudoniem<br>[Sessie, A-public key]
    VAD->>VAD: Maak VP@A<br>[VPP,A-public key]
    VAD->>A: Lever VP@A

    note over A: Verkrijg VP@B
    A->>KL: Verkrijg B public key
    KL->>A: B public key
    A->>VAD: Vraag pseudoniem voor B<br>[Sessie, B-public key]
    VAD->>A: VP@B


```

## Burger log in bij PGO

```mermaid
sequenceDiagram
	actor burger as Karel<br>(PGO gerbuiker)
	participant PGO1
	participant VAD
	participant PAS

	autonumber

	burger ->> PGO1: Klik op "inloggen"
	PGO1 ->> VAD: Verzoek authenticatie<br> voor PGO
	VAD -->> burger: Login prompt

	burger ->> VAD: Log in
	note over VAD: verkrijg BSN
	VAD ->> PAS: Activate BSN
	PAS -->> VAD: polymorf Pseudoniem<br> [PP@VAD]
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
    participant PAS
    participant HA as Huisarts
    participant TSR as Toestemmingen<br> register

    autonumber

    PGO1 ->> VAD: Geef pseudoniem voor Huisarts<br> [HA-ID, Sessie]
    VAD ->> DNS: Haal huidige versie &<br> public key op voor HA<br>[HA-ID]
    DNS->>VAD: Public key HA
    note over VAD: Maak Encrypted Pseudoniem voor HA
    VAD ->> PGO1: EP@HA

    PGO1 ->> HA: Vraag Karel's medische gegevens<br> [EP@HA]
    note over HA: Decrypt EP@HA -> pseudoniem
    HA->>DNS: Lookup public key [TSR-ID]
    DNS->>HA: Public key en versie
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
    participant PAS
    participant NVI as LokalisatieRegister<br> (NVI)
    participant TSR as Toestemmingen<br/>register<br/>(TSR)

    autonumber

    HA ->> PAS: Activeer (BSN)
    PAS -->> HA: PolymorfPseudoniem [PP@HA]


    note over HA: Maak pseudoniem voor <br/>NVI + Toestemmingsregister<br/>[PP@HA, NVI]
    HA ->> NVI: Vraag Karel's zorgaanbieder-lijst<br/> [EP@NVI, EP@TSR]
    NVI ->> TSR: Haal toestemming op<br> [EP@TSR, NVI, Huisarts]
    note over TSR: Decrypt EP@TSR -> Ps@TSR <br> Zoek toestemmingen voor<br> [Ps@TSR, doel=NVI, bron=HA]
    TSR -->> NVI: Toestemmingen
    note over NVI: Decrypt EP@NVI -> Ps@NVI<br> Zoek zorgaanbieders<br> [Ps@NVI, doel=HA]
    NVI -->> HA: [Apotheek1, Huisarts1, Ziekenhuis1]
```


## Registratie voor lokalisatie

```mermaid

sequenceDiagram
    participant HA as Huisarts<br/> (HA)
    participant PAS
    participant NVI as LokalisatieRegister<br> (NVI)

    autonumber

    HA ->> PAS: Activeer (BSN)
    PAS -->> HA: PolymorfPseudoniem [PP@HA]

    HA ->> DNS: Haal versie & public key op van NVI
    DNS ->> HA: Versie & PK

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
HA->>DNS: Registreer nieuwe versie en publieke sleutel

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

participant HA
participant PAS
participant nieuw as Systeem wat nieuwe versie gebruikt

note over PAS: Pas activatie versie & sleutel aan

HA->>PAS: Verifieer activatie versie
PAS->>HA: Geef actuele versie [v2]
note over HA: Zie dat versie anders is en start migratie

nieuw->>HA: Vraag op basis van activatie V2
alt Migratie al gedaan
note over HA: Verwerk als normaal
else Migratie nog niet gedaan
HA->>nieuw: Verzoek om oude versie te gebruiken
nieuw->>PAS: activeer met V1<br>(dit mag enkel tijdelijk)
PAS->>nieuw: oude activatie
nieuw->>HA: V1 versie
end

```

Crypto rollover


```mermaid
sequenceDiagram
autonumber

note over PAS: Nieuwe versie algoritmes...

```