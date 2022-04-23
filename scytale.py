from itertools import chain


from chiffre import Chiffre


FREQUENT_GERMAN_WORDS = [
    "der", "die", "und", "in", "zu", "den", "das", "nicht", "von", "sie", "ist", "des", "sich", "mit",
    "dem", "dass", "er", "es", "ein", "ich", "auf", "so", "eine", "auch", "als", "an", "nach", "wie",
    "im", "für", "man", "aber", "aus", "durch", "wenn", "nur", "war", "noch", "werden", "bei", "hat",
    "wir", "was", "wird", "sein", "einen", "welche", "sind", "oder", "zur", "um", "haben", "einer",
    "mir", "über", "ihm", "diese", "einem", "ihr", "uns", "da", "zum", "kann", "doch", "vor", "dieser",
    "mich", "ihn", "du", "hatte", "seine", "mehr", "am", "denn", "nun", "unter", "sehr", "selbst", "schon",
    "hier", "bis", "habe", "ihre", "dann", "ihnen", "seiner", "alle", "wieder", "meine", "Zeit", "gegen",
    "vom", "ganz", "einzelnen", "wo", "muss", "ohne", "eines", "können", "sei"
]


class ScytaleChiffre(Chiffre):
    r"""
    Die Verschlüsselung
    -------------------
    Die Scytale ist ein Verschiebealgorithmus. Am einfachsten visualisiert
    den Vorgang indem man den Text in Blöcke der Schlüssellänge einteilt
    und die Blöcke in eine Matrix untereinander schreibt. Statt den Text
    Reihe um Reihe zu lesen, liest man ihn nun Spalte um Spalte.

    Die Entschlüsselung
    -------------------
    Die Entschlüsselung funktioniert wie die Verschlüsselung, einzig die
    Schlüssellänge muss angepasst werden und je nach Verschlüsselung ein paar
    Füllzeichen eingefügt werden
    """

    @staticmethod
    def encode(text: str, key: str | int) -> str:
        r"""
        Die Verschiebung
        ----------------
        Zuerst muss sichergestellt werden, dass der Schlüssel eine ganze Zahl
        ist, anschließend wird der Text um soviele Leerzeichen erweitert, dass
        die Textlänge ein Vielfaches des Schlüssels ist. Dann kann die Matrix
        gebaut werden. Diese ist zu diesem Zeitpunkt bereits invertiert (d.h.
        Reihen und Spalten sind bereits vertauscht). Entsprechend muss die
        Matrix nur noch Reihe um Reihe ausgelesen werden

        Parameters
        ----------
        text : str
            Der zuverschlüsselnde Text (beliebige UTF8 Zeichen).
        key : str | int
            Der Schlüssel ist die Blocklänge muss sich in eine Ganzzahl umwandeln lassen.

        Returns
        -------
        str
            Der verschlüsselte Text.

        """
        block_length = int(key)
        squared_text = text + " " * ((block_length - len(text) % block_length) % block_length)
        blocking = [[letter for letter in squared_text[start_idx::block_length]] for start_idx in range(block_length)]
        return ''.join(chain.from_iterable(blocking))

    @staticmethod
    def decode(text: str, key: str | int) -> str:
        r"""
        Decodiert einen mit der Skytale verschlüsselten Text sofern der Schlüssel
        bekannt ist. Der Schlüssel ist hierbei die Textlänge geteilt durch den Schlüssel.
        Eine Umsetzung für verschlüsselte Texte deren Länge kein Vielfaches des Schlüssels
        ist fehlt aktuell noch.

        Parameters
        ----------
        text : str
            Der zu entschlüsselnde Text.
        key : str | int
            Der zum Verschlüsseln verwendete Schlüssel.

        Returns
        -------
        str
            Der entschlüsselte Text.

        """
        return ScytaleChiffre.encode(text, len(text) // key)

    @staticmethod
    def analyse(text: str, max_block_length: int = 100, *args, **kwargs) -> (str, str):
        r"""
        Die Analyse ist eine einfache Bruteforce Attacke in der Schlüssellängen bis
        zur *max_block_length* ausprobiert werden. Der Text in dem die meisten
        deutschen Wörter auftauchen wird als entschlüsselter Text ausgewählt. Die
        Performance kann verbessert werden, indem das Ausprobieren vorzeitig
        abgebrochen wird, wenn ein Text mit deutlich mehr gefunden Wörten auftaucht.

        Parameters
        ----------
        text : str
            Der verschlüsselte Text.

        max_block_length: int = 100
            Die maximale Blocklänge bis zu der ausprobiert wird.

        Returns
        -------
        str, str
            Der entschlüsselte Texte, sowie der Schlüssel

        """
        bruteforce_tries = [ScytaleChiffre.encode(text, len(text) // block) for block in range(2, max_block_length)]
        common_word_hits_tries = [sum(btry.count(word) for word in FREQUENT_GERMAN_WORDS) for btry in bruteforce_tries]
        index_max_agree = common_word_hits_tries.index(max(common_word_hits_tries))
        return bruteforce_tries[index_max_agree], index_max_agree + 2


if __name__ == '__main__':
    with open('example.txt', 'r') as file:
        text = file.read()
    key = 7
    encoded_text = ScytaleChiffre.encode(text, key)
    decoded_text = ScytaleChiffre.decode(encoded_text, key)
    analysed_text, analysed_key = ScytaleChiffre.analyse(encoded_text)
    print(key, analysed_key)
    print(encoded_text)
    print(decoded_text)
