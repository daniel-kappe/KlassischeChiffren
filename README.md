# Klassische Chiffren

Dies ist ein Übungsprojekt für den Kurs "Programmiersprachen
zur Datenanalyse" an der Fachhochschule Bielefeld. In dieser
Übung müssen 3 klassische Verschlüsselungsverfahren, der
Caesar, Skytale und Vignere Chiffe in Python umgesetzt werden.

## Zu den enthaltenden Dateien
`chiffre.py` definiert ein "allgemeines" Interface für die
Implementierungen der Verfahren. Da teils strings und teils
integers als Schlüssel verwendet werden können und teils
beides sind die Typendefinitionen der `Chiffre` Klasse nicht
bindend.

`caesar.py`, `scytale.py` und `vignere.py` sind die jeweiligen
Implementierungen der der Verfahren mit Verschlüsselung,
Entschlüsselung und der Analyse ohne bekannten Schlüssel.

`caesar_min.py` ist eine Fingerübung um zu sehen was die minimale
Anzahl an Zeichen ist um die Caesar Verschlüsselung umzusetzen.
Dabei wurde nahezu alles ignoriert, was guten, lesbaren Code
ausmacht!