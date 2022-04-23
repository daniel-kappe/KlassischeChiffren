#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Mar 28 18:06:29 2022

@author: dkappe
"""
from string import ascii_lowercase, ascii_uppercase
from collections import Counter
from re import sub


from chiffre import Chiffre


LETTER_FREQUENCIES = {
    "A": 0.082, "B": 0.015, "C": 0.027, "D": 0.047, "E": 0.13, "F": 0.022,
    "G": 0.02, "H": 0.062, "I": 0.069, "J": 0.0016, "K": 0.0081, "L": 0.04,
    "M": 0.027, "N": 0.067, "O": 0.078, "P": 0.019, "Q": 0.0011, "R": 0.059,
    "S": 0.062, "T": 0.096, "U": 0.027, "V":	0.0097, "W": 0.024, "X": 0.0015,
    "Y": 0.02, "Z": 0.00078
    }


class CaesarChiffre(Chiffre):
    r"""
    Die Verschlüsselung
    -------------------
    Der Caesar Chiffre ist basiert auf der Verschiebung des Alphabets.
    Basierend auf dem Schlüsselbuchstaben, wird das "A" verschoben und alle
    weiteren Buchstaben um die selbe Distanz. Bei einem Schlüssel von "K" wird
    das "A" -> "K" verschoben, "B" -> "L", "C" -> "M" und so weiter.
    
    Die Entschlüsselung
    -------------------
    Die Decodierung funktioniert analog in die umgekehrte Richtung. Bei der
    Analyse ohne den Schlüssel kann dieser durch eine Freuquenzanalyse der
    Buchstabenhäufigkeiten bestimmt werden.
    """
    
    @staticmethod
    def encode(text: str, key: str | int, *args, **kwargs) -> str:
        r"""
        Die Verschiebung
        ----------------
        Zuerst wird der Schlüssel (Buchstabe) in die Verschiebung umgewandelt.
        Dafür wird der Schlüssel in Großbuchstaben umgewandelt und der ASCII
        Code ausgewertet, das "A" hat einen ASCII Wert von 65, die Differenz
        ergibt die Verschiebung.
        
        Die Verschiebefunktion
        ----------------------
        Groß- und Kleinbuchstaben funktionieren gleich haben nur einen anderen
        Wertebereich 65-90 (groß) 97-122 (klein), entsprechend kann dieselbe
        Funktion für die Verschiebung verwendet werden, es muss nur ein
        unterschiedlicher Offset verwendet werden. `ord(character) - offset`
        ergibt somit einen Wert zwischen 0 und 25. Durch den shift können nun
        negative Werte entstehen, die durch die Modulo 26 Operation wieder in
        den Bereich 0 bis 25 fallen. Schlussendlich bringt die Addition des
        Offset den Wert wieder in die ASCII Groß- und Kleinbuchstaben
        
        Die Übersetzung
        ---------------
        `str.translate(translation_dict)` benötigt ein Dict mit ASCII Codes auf
        einzelnen Character, z.B. {67: 'A', 68: 'B', 69: 'C', ...}. Dieses Dict
        kann mit einer *Dict Comprehension* für die Groß- und Kleinbuchstaben
        aufgebaut werden. mit `{dict1} | {dict2}` werden diese dann zu einer
        Übersetzungstafel zusammengebaut.

        Parameters
        ----------
        text : str
            Der zuverschlüsselnde Text (nur ASCII Zeichen).
        key : str | int
            Der Schlüsselbuchstabe (A-Za-z). Alternativ direkt die Verschiebung.

        Returns
        -------
        str
            Der verschlüsselte Text.

        """
        shift = int(key) if str(key).isdecimal() else ord(key.upper()) - 65
        return text.translate({CaesarChiffre.caesar_shift(ord(letter), shift, True): letter
                               for letter in ascii_lowercase} |
                              {CaesarChiffre.caesar_shift(ord(letter), shift, False): letter
                               for letter in ascii_uppercase})
    
    @staticmethod
    def caesar_shift(ascii_code: int, shift: int, lower: bool = True) -> int:
        r"""
        Nimmt den ASCII Code eines Buchstaben und verschiebt diesen um *shift*
        wobei die lower/uppercase Range erhalten bleibt. Mit *lower* lassen
        sich Kleinbuchstaben nutzen (diese fangen ab Code 97 anstatt 65 an).

        Parameters
        ----------
        ascii_code : int
            Der umzuwandelnde Buchstabe A-Za-z.
        shift : int
            Die Verschiebung des Alphabets.
        lower: bool = True
            Schaltet die Funktion auf die Kleinbuchstaben um.

        Returns
        -------
        int
            ASCII Code des verschobenen Buchstaben.

        """
        offset = 97 if lower else 65
        return (ascii_code - offset - shift) % 26 + offset
    
    @staticmethod
    def decode(text: str, key: str | int, *args, **kwargs) -> str:
        r"""
        Decodiert einen mit Caesar verschlüsselten Text sofern der Schlüssel
        bekannt ist. Die einzige Herausforderung ist es hier den Schlüssel
        umzukehren, sodass die `encode` Methode verwendet werden kann. 156 ist
        dabei `65 * 2 + 26`, zieht man `ord(key.upper())` ab erhält man einen
        Wert zwischen 66("B") und 91("["), letzterer ist nicht ganz sauber,
        funktioniert mit der gewählten Encodierung jedoch problemlos.

        Parameters
        ----------
        text : str
            Der zu entschlüsselnde Text.
        key : str | int
            Der zum Verschlüsseln verwendete Schlüssel. Alternativ direkt die Verschiebung.

        Returns
        -------
        str
            Der entschlüsselte Text.

        """
        return CaesarChiffre.encode(text, 26 - key if str(key).isdecimal() else chr(156 - ord(key.upper())))
    
    @staticmethod
    def analyse(text: str, *args, **kwargs) -> (str, str):
        r"""
        Analysiert die Buchstabenhäufigkeiten in einem verschlüsselten Text und
        ermittelt so den verwendeten Schlüssel und gibt sowohl den
        entschlüsselten Text als auch den verwendeten Schlüssel zurück. Dafür
        wird der Text mit allen möglichen Schlüsseln entschlüsselt und
        anschließend die 

        Parameters
        ----------
        text : str
            Der verschlüsselte Text.

        Returns
        -------
        str, str
            Der entschlüsselte Texte, sowie der Schlüssel

        """
        base_letter_frequencies = CaesarChiffre._calculate_frequencies(text)
        letter_frequencies = {shift:
            {CaesarChiffre.caesar_shift(ascii_code, shift, False): frequency
             for ascii_code, frequency in base_letter_frequencies.items()}
            for shift in range(26)
            }
        shift_deviations = [
            (shift, CaesarChiffre._frequency_distance(frequencies))
            for shift, frequencies in letter_frequencies.items()]
        encryption_key = chr(
            65 + sorted(shift_deviations, key=lambda ent: ent[1])[0][0]
            )
        return CaesarChiffre.decode(text, encryption_key), encryption_key
        
    
    @staticmethod
    def _calculate_frequencies(text: str) -> dict[str, float]:
        text_spaceless = sub('[^A-Z]', '', text.upper())
        return {
            ord(letter): count / len(text_spaceless)
            for letter, count in Counter(text_spaceless).most_common()
            }
    
    @staticmethod
    def _frequency_distance(letter_frequencies: dict[str, float]) -> float:
        return sum((en_frequency - letter_frequencies.get(ord(letter), 0)) ** 2
                   for letter, en_frequency in LETTER_FREQUENCIES.items())


if __name__ == '__main__':
    with open('example.txt', 'r') as file:
        text = file.read()
    key = 'Q'
    encoded_text = CaesarChiffre.encode(text, key)
    decoded_text = CaesarChiffre.decode(encoded_text, key)
    analysed_text, analysed_key = CaesarChiffre.analyse(encoded_text)
    print(key, analysed_key)
    print(encoded_text)
    print(decoded_text)

