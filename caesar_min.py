from string import ascii_uppercase as u, ascii_lowercase as l
def c(t,k):
 f=lambda c,o:(ord(c)-o-ord(k.upper())-65)%26+o
 return t.translate({f(c,65):c for c in u}|{f(c,97):c for c in l})
def d(t,k):
 return c(t,chr(156-ord(k.upper())))