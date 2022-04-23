from itertools import zip_longest, chain
from collections import Counter
from string import ascii_lowercase, ascii_uppercase
from statistics import mean

from chiffre import Chiffre
from caesar import CaesarChiffre


class VignereChiffre(Chiffre):
    r"""
    Die Verschlüsselung
    -------------------
    Der Vignere Chiffre basiert auf dem Caesar Chiffre, allerdings werden hier
    Schlüsselwörter anstatt von Buchstaben verwendet. Jeder Buchstabe des
    Textes wird hier, entsprechend dem Caesar Chiffre, im Alphabet verschoben,
    allerdings gilt für jeden Buchstaben eine andere Verschiebung. Die
    Verschiebungen werden zyklisch aus dem Schlüsselwort genommen

    Beispiel
    --------

    Programmiersprachen zur Datenanalyse
    hallohallohallohallohallohallohalloh
    ------------------------------------
    Wrzrfhmxtsysacojhpy guc Rhtpyouawjgl

    Die Entschlüsselung
    -------------------
    Wie bei der Caesar Chiffre muss hier das Schlüsselwort umgekehrt werden
    um den Text zu dechiffrieren.
    """

    @staticmethod
    def encode(text: str, key: str) -> str:
        r"""
        Die Verschiebung
        ----------------
        Im Gegensatz zur Caesar Chiffre werden hier mehrere Übersetzungsdicts
        enötigt. Diese werden unter zur Hilfenahme der Funktion aus dem Caesar
        Chiffre aufgebaut für jeden Buchstaben des Schlüsselworts. Anschließend
        wird der Text in Blöcke aufgeteilt, die den selben Schlüsselbuchstaben
        haben und diese dann zusammen übersetzt. Zum Schluss muss der Text wieder
        in der richtigen Reihenfolge zusammengesetzt werden.


        Parameters
        ----------
        text : str
            Der zuverschlüsselnde Text (nur ASCII Buchstaben).
        key : str
            Das Schlüsselwort

        Returns
        -------
        str
            Der verschlüsselte Text.
        """
        shifts = [ord(letter.upper()) - 65 for letter in key]
        translate_dicts = [{CaesarChiffre.caesar_shift(ord(letter), shift, True): letter
                            for letter in ascii_lowercase} |
                           {CaesarChiffre.caesar_shift(ord(letter), shift, False): letter
                            for letter in ascii_uppercase}
                           for shift in shifts]
        encoded_text = [''.join([text[group_idx::len(key)]]) for group_idx in range(len(key))]
        encoded_text = [group.translate(translate_dict)for group, translate_dict in zip(encoded_text, translate_dicts)]
        return ''.join([''.join(group_letters) for group_letters in zip_longest(*encoded_text, fillvalue='')])

    @staticmethod
    def decode(text: str, key: str) -> str:
        r"""
        Zur Entschlüsselung muss nur das Schlüsselwort angepasst werden, anschließend
        kann die Verschlüsselungsmethode verwendet werden.

        Parameters
        ----------
        text : str
            Der zu entschlüsselnde Text.
        key : str
            Der zum Verschlüsseln verwendete Schlüssel.

        Returns
        -------
        str
            Der entschlüsselte Text.

        """
        decrypt_key = ''.join([chr(156 - ord(letter.upper())) for letter in key])
        return VignereChiffre.encode(text, decrypt_key)

    @staticmethod
    def _calculate_index_coincidence(text: str) -> float:
        r"""
        Berechnet den Koinzidenzindex nach https://de.wikipedia.org/wiki/Koinzidenzindex

        Parameters
        ----------
        text: str
            Der Text für den der Koinzidenzindex berechnet werden soll.

        Returns
        -------
        float
            Der berechnete Koinzidenzindex
        """
        frequency = Counter(text)
        length = len(text)
        return sum(value * (value - 1) for value in frequency.values()) / (length * (length - 1))

    @staticmethod
    def analyse(text: str, max_key_length: int = 30, *args, **kwargs) -> (str, str):
        r"""
        Als erstes muss die Schlüssellänge berechnet werden. Hierzu wird der
        Koinzidenzindex verwendet. In einer Bruteforce Methode wird der
        Koinzidenzindex für Schlüssellängen bis zur *max_key_length* berechnet
        Die Schlüssellänge (bei ausreichend langen Texten) ist diejenige mit
        dem höchsten Index (zumindest ein vielfaches der Schlüssellänge)
        entsprechend wird die Länge genommen mit dem fast höchsten Index aber
        der kürzesten Schlüssellänge.

        Parameters
        ----------
        text : str
            Der verschlüsselte Text.

        max_key_length: int = 30
            Die maximale Schlüssellänge bis zu der ausprobiert wird.

        Returns
        -------
        str, str
            Der entschlüsselte Texte, sowie der Schlüssel

        """
        upper_text = text.upper()
        coincidences = [
            mean(VignereChiffre._calculate_index_coincidence(upper_text[group_idx::key_length])
                 for group_idx in range(key_length))
            for key_length in range(1, max_key_length + 1)
        ]
        shortest_likely = min(idx + 1 for idx, coincidence in enumerate(coincidences)
                              if coincidence > max(coincidences) * 0.95)
        decrypted = [CaesarChiffre.analyse(text[start::shortest_likely]) for start in range(shortest_likely)]
        message = [letters for letters in zip_longest(*[item[0] for item in decrypted], fillvalue='')]
        return (''.join(chain.from_iterable(message)), ''.join(item[1] for item in decrypted))


if __name__ == '__main__':
    with open('example.txt', 'r') as file:
        text = file.read()
    key = 'AveCaesarHowAreYou'
    encoded_text = VignereChiffre.encode(text, key)
    decoded_text = VignereChiffre.decode(encoded_text, key)
    analysed_text, analysed_key = VignereChiffre.analyse(encoded_text, max_key_length=30)
    print(key, analysed_key)
    print(encoded_text)
    print(decoded_text)
    print(VignereChiffre.encode('Programmiersprachen zur Datenanalyse', 'hallo'))
