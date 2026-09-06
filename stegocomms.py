"""
stegocomms.py -- Proof of Concept v4

Covert, encrypted message channel over any text transport.
This version is BYTE-COMPATIBLE with the browser tool cover_studio.html:
a cover produced in the browser decodes here and vice versa.

Dependencies:  pip install cryptography      (zlib/hashlib = standard library)

Pipeline (sender):
  plaintext -> zlib(deflate) -> AES-256-GCM (iv||ciphertext||tag)
    -> pad to a multiple of CHUNK -> K data blocks
    -> +R cross-block parity (Reed-Solomon over GF(256), Cauchy matrix -> MDS)
    -> per block: idx || payload || CRC8, masked with a keystream
    -> bits rendered as cover sentences (density varies by "level")
    -> leftover bits filled with key-derived random padding
The receiver runs it backwards; a per-block CRC spots damaged blocks and treats
them as erasures -> reconstructed up to the parity limit WITHOUT asking for a
resend, beyond that a NACK naming the missing data blocks.

What changed in v4 compared to v3
---------------------------------
1. No plaintext header any more.  v3 prefixed every block with a line
   "DE W1ABC MSG 0/12 K 10 SZ 74 LV 0 CK 8" -- in a chat transport by far the
   most conspicuous element of the whole cover.  In v4 the block index and the
   block CRC live in the sentence bits, and the fields that are constant per
   message (K, R, ciphertext padding, block nonce) live in a MANIFEST which is
   itself made of ordinary cover sentences.  A cover therefore consists of
   nothing but chat sentences.
   The manifest is masked with a key-derived keystream; without the passphrase
   it cannot be told apart from a payload block.  It is sent twice (start and
   end, with different nonces and therefore completely different wording) so
   that losing one spot does not cost the whole message.
   Language and level are NOT stored -- the receiver tries all 8 combinations
   and lets the manifest CRC16 decide.

2. Density instead of length.  In v3 the higher levels bought their bits by
   appending clauses: a tacked-on clause carried ~5 bits but cost ~20
   characters -- a worse ratio than the base sentence.  Density per character
   therefore FELL as the level rose (0.31 -> 0.26 bits/char) and "very terse"
   produced MORE characters than "very believable".  In v4 the sentence stays
   short and the word lists get wider (8/16/32 options = 3/4/5 bits per slot);
   level 3 additionally drops articles and verbs for a telegraphic style.
   Believability now falls through unusual word choice rather than length --
   and the character count falls monotonically with the level.

3. Correct articles in German ("der Kaffee", "die Antenne") instead of v3's
   blanket "das".

v3 covers can NOT be decoded with v4 (different wire format and a different
PBKDF2 salt).

Key:  derived from the shared passphrase via PBKDF2-HMAC-SHA256
      (salt "stegocomm/v4/pbkdf2", 200_000 iterations, 32 bytes).
      Both sides must use the same passphrase.
"""

import sys, os, re, math, zlib, hashlib, secrets, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 8            # bytes per block
BLOCK_BITS = CHUNK * 8   # 64
PBKDF2_SALT = b"stegocomm/v5/pbkdf2"
PBKDF2_ITERS = 200_000

# Field sizes (bytes) of the two frame types
MNONCE_LEN = 2                     # manifest nonce, sent in the clear
BNONCE_LEN = 2                     # block nonce, masked inside the manifest
# K | R | pad length | bnonce | crc16 -- the ciphertext length is carried as a
# 3-bit pad length (ctlen = K*CHUNK - pad) rather than as a 16-bit number.
MANIFEST_PLAIN = 1 + 1 + 1 + BNONCE_LEN + 2                   # 7 bytes
MANIFEST_LEN = MNONCE_LEN + MANIFEST_PLAIN                    # 9 bytes
MANIFEST_BITS = MANIFEST_LEN * 8                              # 72
BLOCK_FRAME = 1 + CHUNK + 1        # idx | payload | crc8 = 10 bytes
FRAME_BITS = BLOCK_FRAME * 8       # 80

MAX_BLOCKS = 254                   # idx fits in one byte, 255 stays reserved

# --------------------------------------------------------- GF(256) arithmetic
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]

def gmul(a, b):
    return 0 if (a == 0 or b == 0) else _EXP[_LOG[a] + _LOG[b]]

def ginv(a):
    return _EXP[255 - _LOG[a]]

def cauchy(R, K):
    """Cauchy encoding matrix R x K -- every square submatrix is invertible (MDS)."""
    P = []
    for r in range(R):
        xr = 255 - r                       # xr != i guaranteed (see the encode limit)
        P.append([ginv(xr ^ i) for i in range(K)])
    return P

def _unit(i, n):
    row = [0] * n
    row[i] = 1
    return row

def mat_inv(M, n):
    """GF(256) matrix inverse via Gauss-Jordan; None if singular."""
    A = [list(row) for row in M]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        p = c
        while p < n and A[p][c] == 0:
            p += 1
        if p == n:
            return None
        if p != c:
            A[p], A[c] = A[c], A[p]
            I[p], I[c] = I[c], I[p]
        inv = ginv(A[c][c])
        A[c] = [gmul(v, inv) for v in A[c]]
        I[c] = [gmul(v, inv) for v in I[c]]
        for r in range(n):
            if r == c:
                continue
            f = A[r][c]
            if f == 0:
                continue
            A[r] = [A[r][j] ^ gmul(f, A[c][j]) for j in range(n)]
            I[r] = [I[r][j] ^ gmul(f, I[c][j]) for j in range(n)]
    return I

# --------------------------------------------------------- bit helpers + CRC
def bytes_to_bits(bs):
    bits = []
    for b in bs:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits):
    out = bytearray(len(bits) // 8)
    for i in range(len(out)):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i * 8 + j]
        out[i] = v
    return bytes(out)

def crc16(bs):
    """CRC-16-CCITT (0x1021, init 0xFFFF, no reflection) -- exactly as in the GUI."""
    c = 0xffff
    for b in bs:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xffff if (c & 0x8000) else (c << 1) & 0xffff
    return c & 0xffff

# --------------------------------------------------------- grammars DE/EN
# Slots that carry the theme, per topic. Everything else is shared, because
# only the nouns need to differ: the noun identifies the topic, so every other
# slot can use one list whose indices mean the same thing in every topic.
#
# The bare nouns are unique across EVERY topic and both lists. That rule is
# what lets a receiver decode a cover no matter which topics the sender had
# switched on -- the topic choice carries no data at all, it only decides
# which words the encoder draws from.
TOPIC_ORDER = ["weather", "home", "garden", "work", "travel", "tech"]
DEFAULT_TOPICS = ["weather", "home", "garden", "work", "travel"]
AFU_TOPICS = ["tech"]

TOPIC_WORDS = {
    "de": {
        "weather": {"N": [
            "das wetter", "der himmel", "der regen", "der wind", "die sonne", "die wolke",
            "das licht", "der nebel", "der schnee", "der frost", "der sturm", "der mond",
            "der stern", "die luft", "der schatten", "das eis", "der hagel", "der donner",
            "der blitz", "der tau", "die hitze", "die kaelte", "die waerme", "die boe",
            "das gewitter", "der schauer", "die daemmerung", "die feuchte", "das glatteis",
            "die nachtluft", "die morgenluft", "die wolkendecke", "das dach",
            "die strasse", "das feld", "die wiese", "der bach", "der huegel", "das tal",
            "das ufer", "der wald", "der pfad", "die kuppe", "die senke", "die klippe",
            "die duene", "das moor", "die heide", "der horizont", "die brise", "der orkan",
            "der graupel", "der reif", "der dunst", "die schwaden", "die front",
            "der hochdruck", "der tiefdruck", "das sonnenlicht", "das mondlicht",
            "die windstille", "die wetterlage", "das abendrot", "das morgenrot"
        ]},
        "home": {"N": [
            "der kaffee", "der tee", "das brot", "die suppe", "die pfanne", "der topf",
            "der ofen", "der tisch", "der stuhl", "die lampe", "der teppich", "das regal",
            "der schrank", "der herd", "der besen", "der becher", "der teig",
            "der vorhang", "das sofa", "die spuele", "der kuehlschrank", "der kessel",
            "der teller", "der loeffel", "das messer", "die gabel", "die kanne",
            "die schuessel", "das backblech", "die muehle", "das waschbecken",
            "der waeschekorb", "der flur", "die kueche", "die kammer", "der keller",
            "der boden", "die treppe", "die tuer", "das fenster", "die wand", "die decke",
            "die ecke", "die nische", "die diele", "die speisekammer", "der abstellraum",
            "das badezimmer", "das sieb", "das brett", "die dose", "das glas",
            "die flasche", "der korken", "die serviette", "das tuch", "der schwamm",
            "der lappen", "die buerste", "die seife", "der muell", "die tonne",
            "der vorrat", "die kiste"
        ]},
        "garden": {"N": [
            "der garten", "das beet", "der rasen", "die hecke", "der baum", "der strauch",
            "die blume", "die rose", "das kraut", "der salat", "die tomate",
            "die kartoffel", "der apfel", "die birne", "die kirsche", "das laub",
            "die tulpe", "die zwetschge", "die erdbeere", "die gurke", "die bohne",
            "die erbse", "die moehre", "die zwiebel", "der knoblauch", "der kompost",
            "die wurzel", "der samen", "die knospe", "die bluete", "der zweig",
            "die rinde", "der schuppen", "der zaun", "das gartentor", "die giesskanne",
            "die schaufel", "die harke", "die schubkarre", "das gewaechshaus",
            "das hochbeet", "die regentonne", "die gartenbank", "die laube", "die pergola",
            "das spalier", "das rankgitter", "der kiesweg", "der spaten", "die schere",
            "der eimer", "der sack", "die erde", "der mulch", "der duenger", "der halm",
            "die ranke", "der dorn", "der stiel", "das blatt", "die schnecke", "die biene",
            "die hummel", "die amsel"
        ]},
        "work": {"N": [
            "der plan", "der termin", "die sitzung", "der bericht", "die akte",
            "die mappe", "die notiz", "die liste", "die aufgabe", "die frist",
            "der vertrag", "die rechnung", "das angebot", "der kunde", "der kollege",
            "die pause", "der chef", "die schicht", "das buero", "der schreibtisch",
            "der drucker", "der ordner", "der kalender", "das protokoll", "die vorlage",
            "der entwurf", "die freigabe", "die abnahme", "der urlaub", "der dienstplan",
            "die ablage", "der posteingang", "die kantine", "der empfang", "das lager",
            "die werkstatt", "die halle", "der aufzug", "der parkplatz", "die pforte",
            "das archiv", "die poststelle", "der konferenzraum", "die teekueche",
            "der aushang", "der dienstweg", "der schichtplan", "die zeiterfassung",
            "der antrag", "das formular", "der stempel", "die unterschrift", "der anruf",
            "das telefon", "die besprechung", "die abteilung", "das budget",
            "die kennzahl", "die bilanz", "die prognose", "das quartal", "der umsatz",
            "die zulage", "der beleg"
        ]},
        "travel": {"N": [
            "der zug", "der bus", "die bahn", "das gleis", "der bahnsteig", "der fahrplan",
            "das ticket", "der koffer", "der rucksack", "die karte", "die strecke",
            "der stau", "die ampel", "die kreuzung", "der hafen", "die abfahrt",
            "die route", "die umleitung", "die tankstelle", "die raststaette",
            "die autobahn", "die landstrasse", "die faehre", "der flughafen",
            "das gepaeck", "der anschluss", "die verspaetung", "die ankunft",
            "die haltestelle", "das fahrrad", "der roller", "der wanderweg", "die bruecke",
            "der tunnel", "die kurve", "die steigung", "das gefaelle", "der rastplatz",
            "die parkbucht", "die schranke", "die unterfuehrung", "der wegweiser",
            "der meilenstein", "die grenze", "das zollhaus", "die mautstelle",
            "der seitenstreifen", "die standspur", "die reise", "die fahrt", "das abteil",
            "der waggon", "der schaffner", "die spur", "die rampe", "die ausfahrt",
            "die einfahrt", "der kilometer", "das benzin", "der motor", "der reifen",
            "die bremse", "das lenkrad", "der spiegel"
        ]},
        "tech": {"N": [
            "das signal", "das band", "der funk", "die antenne", "das radio", "das netz",
            "der strom", "das kabel", "der draht", "der sender", "das rauschen",
            "der pegel", "die frequenz", "die batterie", "der schalter", "der stecker",
            "der empfaenger", "der verstaerker", "das filter", "die modulation",
            "der akku", "das ladegeraet", "die platine", "die sicherung", "das messgeraet",
            "das oszilloskop", "der loetkolben", "der widerstand", "der kondensator",
            "die spule", "das relais", "das mikrofon", "der mast", "der turm",
            "die speisung", "die erdung", "das koaxkabel", "der balun", "der tuner",
            "der dipol", "die yagi", "die groundplane", "der vorverstaerker",
            "das netzteil", "das gehaeuse", "der luefter", "der kuehlkoerper",
            "die steckdose", "der knopf", "der regler", "die anzeige", "die skala",
            "die litze", "das loetzinn", "die buchse", "die klemme", "die drossel",
            "die diode", "der transistor", "der quarz", "das funkgeraet", "die handfunke",
            "die rauschsperre", "die feldstaerke"
        ]},
    },
    "en": {
        "weather": {"N": [
            "the weather", "the sky", "the rain", "the wind", "the sun", "the cloud",
            "the daylight", "the fog", "the snow", "the frost", "the storm", "the moon",
            "the star", "the air", "the shade", "the ice", "the hail", "the thunder",
            "the lightning", "the dew", "the heat", "the chill", "the warmth", "the gust",
            "the drizzle", "the shower", "the dusk", "the humidity", "the sleet",
            "the nightair", "the morningair", "the greyness", "the roof", "the road",
            "the field", "the meadow", "the brook", "the hill", "the valley", "the shore",
            "the wood", "the trail", "the ridge", "the dell", "the cliff", "the dune",
            "the moor", "the heath", "the horizon", "the breeze", "the gale", "the squall",
            "the rime", "the mist", "the vapour", "the front", "the trough",
            "the sunlight", "the moonlight", "the stillness", "the forecast", "the sunset",
            "the sunrise", "the daybreak"
        ]},
        "home": {"N": [
            "the coffee", "the tea", "the bread", "the soup", "the pan", "the pot",
            "the oven", "the table", "the chair", "the lamp", "the carpet", "the shelf",
            "the cupboard", "the stove", "the broom", "the mug", "the dough",
            "the curtain", "the sofa", "the sink", "the fridge", "the kettle", "the plate",
            "the spoon", "the knife", "the fork", "the jug", "the bowl", "the tray",
            "the grinder", "the basin", "the hamper", "the hallway", "the kitchen",
            "the pantry", "the cellar", "the floor", "the staircase", "the door",
            "the window", "the wall", "the ceiling", "the corner", "the alcove",
            "the landing", "the larder", "the closet", "the bathroom", "the sieve",
            "the plank", "the tin", "the glass", "the bottle", "the cork", "the napkin",
            "the cloth", "the sponge", "the rag", "the brush", "the soap", "the rubbish",
            "the bin", "the stock", "the crate"
        ]},
        "garden": {"N": [
            "the garden", "the bed", "the lawn", "the hedge", "the tree", "the shrub",
            "the flower", "the rose", "the herb", "the lettuce", "the tomato",
            "the potato", "the apple", "the pear", "the cherry", "the leaf", "the tulip",
            "the plum", "the strawberry", "the cucumber", "the bean", "the pea",
            "the carrot", "the onion", "the garlic", "the compost", "the root", "the seed",
            "the bud", "the blossom", "the twig", "the bark", "the shed", "the fence",
            "the gate", "the hose", "the spade", "the rake", "the barrow",
            "the greenhouse", "the planter", "the waterbutt", "the bench", "the arbour",
            "the pergola", "the trellis", "the lattice", "the gravelpath", "the shears",
            "the bucket", "the sack", "the soil", "the mulch", "the fertiliser",
            "the stem", "the tendril", "the thorn", "the stalk", "the snail", "the bee",
            "the bumblebee", "the blackbird", "the dibber", "the sapling"
        ]},
        "work": {"N": [
            "the plan", "the appointment", "the meeting", "the report", "the file",
            "the folder", "the note", "the list", "the task", "the deadline",
            "the contract", "the invoice", "the quote", "the client", "the colleague",
            "the break", "the boss", "the shift", "the office", "the desk", "the printer",
            "the binder", "the calendar", "the minutes", "the template", "the draft",
            "the approval", "the handover", "the holiday", "the rota", "the filing",
            "the inbox", "the canteen", "the reception", "the warehouse", "the workshop",
            "the hall", "the lift", "the carpark", "the gatehouse", "the archive",
            "the postroom", "the boardroom", "the kitchenette", "the noticeboard",
            "the procedure", "the roster", "the timesheet", "the application", "the form",
            "the stamp", "the signature", "the call", "the phone", "the briefing",
            "the department", "the budget", "the metric", "the balance", "the projection",
            "the quarter", "the turnover", "the allowance", "the receipt"
        ]},
        "travel": {"N": [
            "the train", "the bus", "the tram", "the track", "the platform",
            "the timetable", "the ticket", "the suitcase", "the rucksack", "the map",
            "the route", "the jam", "the crossing", "the junction", "the harbour",
            "the departure", "the leg", "the diversion", "the garage", "the services",
            "the motorway", "the lane", "the ferry", "the airport", "the luggage",
            "the connection", "the delay", "the arrival", "the stop", "the bicycle",
            "the scooter", "the footpath", "the bridge", "the tunnel", "the bend",
            "the climb", "the descent", "the layby", "the verge", "the barrier",
            "the underpass", "the signpost", "the milestone", "the border",
            "the tollbooth", "the checkpoint", "the hardshoulder", "the sliproad",
            "the journey", "the ride", "the compartment", "the carriage", "the conductor",
            "the ramp", "the exit", "the entrance", "the kilometre", "the petrol",
            "the engine", "the tyre", "the brake", "the wheel", "the mirror", "the wing"
        ]},
        "tech": {"N": [
            "the signal", "the band", "the radio", "the antenna", "the network",
            "the power", "the cable", "the wire", "the noise", "the level",
            "the frequency", "the battery", "the switch", "the plug", "the fuse",
            "the meter", "the receiver", "the transmitter", "the amplifier", "the filter",
            "the modulation", "the charger", "the board", "the scope", "the solder",
            "the resistor", "the capacitor", "the coil", "the relay", "the microphone",
            "the mains", "the feed", "the mast", "the tower", "the feedline", "the earth",
            "the coax", "the balun", "the tuner", "the dipole", "the yagi",
            "the groundplane", "the preamp", "the psu", "the case", "the fan",
            "the heatsink", "the socket", "the knob", "the dial", "the gauge", "the scale",
            "the strand", "the flux", "the jack", "the clamp", "the choke", "the diode",
            "the transistor", "the crystal", "the handheld", "the squelch",
            "the fieldstrength", "the rig"
        ]},
    },
}

# Shared by every topic.
SHARED_POOLS = {
    "de": {
        "A1": [
            "gut", "fein", "mau", "stark", "ruhig", "laut", "stetig", "klar", "matt",
            "zaeh", "frisch", "flach", "dicht", "fest", "mild", "rau", "schwach", "hart",
            "weich", "glatt", "steil", "eng", "breit", "tief", "hoch", "kurz", "lang",
            "dumpf", "spitz", "grob", "zart", "schroff", "bereit", "spaet", "nah",
            "fertig", "offen", "langsam", "knapp", "leer", "voll", "frei", "sicher",
            "locker", "straff", "schief", "gerade", "sauber", "neu", "alt", "heil",
            "krumm", "rund", "eckig", "leicht", "schwer", "hohl", "massiv", "roh", "blank",
            "stumpf", "wach", "muede", "derb"
        ],
        "A2": [
            "warm", "kuehl", "still", "windig", "hell", "trueb", "trocken", "feucht",
            "sonnig", "wolkig", "kalt", "lau", "diesig", "klamm", "schwuel", "frostig",
            "eisig", "stickig", "zugig", "prall", "milchig", "grau", "blass", "fahl",
            "dunstig", "regnerisch", "bedeckt", "heiter", "mondhell", "sternklar",
            "taufrisch", "windstill"
        ],
        "END": [
            "hier", "jetzt", "wieder", "noch", "heute", "gleich", "spaeter", "morgen",
            "abends", "nachts", "drinnen", "draussen", "oben", "unten", "vorn", "hinten",
            "nebenan", "gegenueber", "ringsum", "ueberall", "nirgends", "zuhause",
            "weiterhin", "momentan", "derzeit", "neuerdings", "seither", "mittags",
            "sonntags", "wochentags", "vorhin", "danach"
        ],
        "ADV2": [
            "gleich", "spaeter", "heute", "morgen", "abends", "nachts", "frueh", "bald",
            "jetzt", "dann", "eben", "stets", "oft", "selten", "immer", "nie", "gestern",
            "vorgestern", "uebermorgen", "taeglich", "stuendlich", "jaehrlich",
            "monatlich", "anfangs", "zuletzt", "zeitweise", "laufend", "erneut",
            "wiederholt", "gelegentlich", "kaum", "sofort"
        ],
    },
    "en": {
        "A1": [
            "good", "fine", "poor", "strong", "quiet", "noisy", "steady", "clear", "dull",
            "tough", "fresh", "flat", "dense", "firm", "mild", "rough", "weak", "hard",
            "soft", "smooth", "steep", "narrow", "wide", "deep", "high", "short", "long",
            "muffled", "sharp", "coarse", "tender", "harsh", "ready", "late", "close",
            "set", "open", "slow", "tight", "empty", "full", "free", "safe", "loose",
            "taut", "crooked", "straight", "clean", "new", "old", "whole", "bent", "round",
            "square", "light", "heavy", "hollow", "solid", "raw", "plain", "blunt",
            "awake", "weary", "silent"
        ],
        "A2": [
            "warm", "cool", "calm", "windy", "bright", "cloudy", "dry", "damp", "sunny",
            "overcast", "cold", "mellow", "hazy", "clammy", "muggy", "frosty", "icy",
            "stuffy", "drafty", "plump", "milky", "grey", "pale", "wan", "misty", "rainy",
            "dim", "fair", "starlit", "moonlit", "dewy", "hushed"
        ],
        "END": [
            "here", "now", "again", "still", "today", "soon", "later", "tomorrow",
            "tonight", "outside", "inside", "upstairs", "downstairs", "ahead", "behind",
            "nearby", "nextdoor", "opposite", "around", "everywhere", "nowhere", "athome",
            "meanwhile", "currently", "recently", "since", "midday", "sundays", "weekdays",
            "earlier", "afterwards", "elsewhere"
        ],
        "ADV2": [
            "soon", "later", "today", "tomorrow", "tonight", "overnight", "early",
            "shortly", "now", "then", "briefly", "lately", "often", "rarely", "always",
            "never", "yesterday", "weekly", "daily", "hourly", "yearly", "monthly",
            "initially", "finally", "occasionally", "repeatedly", "hardly", "seldom",
            "twice", "once", "afresh", "promptly"
        ],
    },
}

# Slot name -> word list.  A "b" prefix renders the form without its article.
# n1/b1 come from the topic, everything else from the shared pools.
SLOT_POOL = {"n1": "N", "b1": "N",
             "a1": "A1", "a2": "A2", "end": "END", "adv2": "ADV2"}

# {slot:count} -- count is the prefix length used and must be a power of two.
# No punctuation anywhere: every character has to survive the transport, and
# a comma is exactly what a radio or chat path quietly drops.
#
# Each level offers several shapes of identical word count and bit width, and
# which one is used is itself part of the payload -- so the variety is free,
# adding log2(count) bits per sentence rather than costing anything. Levels 0
# to 2 get eight verbs times two word orders; level 3 permutes its four words.
TEMPLATES = {
    "de": [
        [
            "{n1:16} ist {a1:8} {end:8}",
            "{n1:16} war {a1:8} {end:8}",
            "{n1:16} bleibt {a1:8} {end:8}",
            "{n1:16} blieb {a1:8} {end:8}",
            "{n1:16} wirkt {a1:8} {end:8}",
            "{n1:16} wirkte {a1:8} {end:8}",
            "{n1:16} scheint {a1:8} {end:8}",
            "{n1:16} schien {a1:8} {end:8}",
            "{end:8} ist {n1:16} {a1:8}",
            "{end:8} war {n1:16} {a1:8}",
            "{end:8} bleibt {n1:16} {a1:8}",
            "{end:8} blieb {n1:16} {a1:8}",
            "{end:8} wirkt {n1:16} {a1:8}",
            "{end:8} wirkte {n1:16} {a1:8}",
            "{end:8} scheint {n1:16} {a1:8}",
            "{end:8} schien {n1:16} {a1:8}",
        ],
        [
            "{n1:32} ist {a1:16} {end:16}",
            "{n1:32} war {a1:16} {end:16}",
            "{n1:32} bleibt {a1:16} {end:16}",
            "{n1:32} blieb {a1:16} {end:16}",
            "{n1:32} wirkt {a1:16} {end:16}",
            "{n1:32} wirkte {a1:16} {end:16}",
            "{n1:32} scheint {a1:16} {end:16}",
            "{n1:32} schien {a1:16} {end:16}",
            "{end:16} ist {n1:32} {a1:16}",
            "{end:16} war {n1:32} {a1:16}",
            "{end:16} bleibt {n1:32} {a1:16}",
            "{end:16} blieb {n1:32} {a1:16}",
            "{end:16} wirkt {n1:32} {a1:16}",
            "{end:16} wirkte {n1:32} {a1:16}",
            "{end:16} scheint {n1:32} {a1:16}",
            "{end:16} schien {n1:32} {a1:16}",
        ],
        [
            "{b1:64} ist {a1:32} {a2:16} {end:16}",
            "{b1:64} war {a1:32} {a2:16} {end:16}",
            "{b1:64} bleibt {a1:32} {a2:16} {end:16}",
            "{b1:64} blieb {a1:32} {a2:16} {end:16}",
            "{b1:64} wirkt {a1:32} {a2:16} {end:16}",
            "{b1:64} wirkte {a1:32} {a2:16} {end:16}",
            "{b1:64} scheint {a1:32} {a2:16} {end:16}",
            "{b1:64} schien {a1:32} {a2:16} {end:16}",
            "{end:16} ist {b1:64} {a1:32} {a2:16}",
            "{end:16} war {b1:64} {a1:32} {a2:16}",
            "{end:16} bleibt {b1:64} {a1:32} {a2:16}",
            "{end:16} blieb {b1:64} {a1:32} {a2:16}",
            "{end:16} wirkt {b1:64} {a1:32} {a2:16}",
            "{end:16} wirkte {b1:64} {a1:32} {a2:16}",
            "{end:16} scheint {b1:64} {a1:32} {a2:16}",
            "{end:16} schien {b1:64} {a1:32} {a2:16}",
        ],
        [
            "{b1:64} {a1:64} {adv2:32} {a2:32}",
            "{b1:64} {a1:64} {a2:32} {adv2:32}",
            "{b1:64} {adv2:32} {a1:64} {a2:32}",
            "{b1:64} {adv2:32} {a2:32} {a1:64}",
            "{b1:64} {a2:32} {a1:64} {adv2:32}",
            "{b1:64} {a2:32} {adv2:32} {a1:64}",
            "{a1:64} {b1:64} {adv2:32} {a2:32}",
            "{a1:64} {b1:64} {a2:32} {adv2:32}",
            "{a1:64} {adv2:32} {b1:64} {a2:32}",
            "{a1:64} {adv2:32} {a2:32} {b1:64}",
            "{a1:64} {a2:32} {b1:64} {adv2:32}",
            "{a1:64} {a2:32} {adv2:32} {b1:64}",
            "{adv2:32} {b1:64} {a1:64} {a2:32}",
            "{adv2:32} {b1:64} {a2:32} {a1:64}",
            "{adv2:32} {a1:64} {b1:64} {a2:32}",
            "{adv2:32} {a1:64} {a2:32} {b1:64}",
        ],
    ],
    "en": [
        [
            "{n1:16} is {a1:8} {end:8}",
            "{n1:16} was {a1:8} {end:8}",
            "{n1:16} stays {a1:8} {end:8}",
            "{n1:16} stayed {a1:8} {end:8}",
            "{n1:16} seems {a1:8} {end:8}",
            "{n1:16} seemed {a1:8} {end:8}",
            "{n1:16} looks {a1:8} {end:8}",
            "{n1:16} looked {a1:8} {end:8}",
            "{end:8} {n1:16} is {a1:8}",
            "{end:8} {n1:16} was {a1:8}",
            "{end:8} {n1:16} stays {a1:8}",
            "{end:8} {n1:16} stayed {a1:8}",
            "{end:8} {n1:16} seems {a1:8}",
            "{end:8} {n1:16} seemed {a1:8}",
            "{end:8} {n1:16} looks {a1:8}",
            "{end:8} {n1:16} looked {a1:8}",
        ],
        [
            "{n1:32} is {a1:16} {end:16}",
            "{n1:32} was {a1:16} {end:16}",
            "{n1:32} stays {a1:16} {end:16}",
            "{n1:32} stayed {a1:16} {end:16}",
            "{n1:32} seems {a1:16} {end:16}",
            "{n1:32} seemed {a1:16} {end:16}",
            "{n1:32} looks {a1:16} {end:16}",
            "{n1:32} looked {a1:16} {end:16}",
            "{end:16} {n1:32} is {a1:16}",
            "{end:16} {n1:32} was {a1:16}",
            "{end:16} {n1:32} stays {a1:16}",
            "{end:16} {n1:32} stayed {a1:16}",
            "{end:16} {n1:32} seems {a1:16}",
            "{end:16} {n1:32} seemed {a1:16}",
            "{end:16} {n1:32} looks {a1:16}",
            "{end:16} {n1:32} looked {a1:16}",
        ],
        [
            "{b1:64} is {a1:32} {a2:16} {end:16}",
            "{b1:64} was {a1:32} {a2:16} {end:16}",
            "{b1:64} stays {a1:32} {a2:16} {end:16}",
            "{b1:64} stayed {a1:32} {a2:16} {end:16}",
            "{b1:64} seems {a1:32} {a2:16} {end:16}",
            "{b1:64} seemed {a1:32} {a2:16} {end:16}",
            "{b1:64} looks {a1:32} {a2:16} {end:16}",
            "{b1:64} looked {a1:32} {a2:16} {end:16}",
            "{end:16} {b1:64} is {a1:32} {a2:16}",
            "{end:16} {b1:64} was {a1:32} {a2:16}",
            "{end:16} {b1:64} stays {a1:32} {a2:16}",
            "{end:16} {b1:64} stayed {a1:32} {a2:16}",
            "{end:16} {b1:64} seems {a1:32} {a2:16}",
            "{end:16} {b1:64} seemed {a1:32} {a2:16}",
            "{end:16} {b1:64} looks {a1:32} {a2:16}",
            "{end:16} {b1:64} looked {a1:32} {a2:16}",
        ],
        [
            "{b1:64} {a1:64} {adv2:32} {a2:32}",
            "{b1:64} {a1:64} {a2:32} {adv2:32}",
            "{b1:64} {adv2:32} {a1:64} {a2:32}",
            "{b1:64} {adv2:32} {a2:32} {a1:64}",
            "{b1:64} {a2:32} {a1:64} {adv2:32}",
            "{b1:64} {a2:32} {adv2:32} {a1:64}",
            "{a1:64} {b1:64} {adv2:32} {a2:32}",
            "{a1:64} {b1:64} {a2:32} {adv2:32}",
            "{a1:64} {adv2:32} {b1:64} {a2:32}",
            "{a1:64} {adv2:32} {a2:32} {b1:64}",
            "{a1:64} {a2:32} {b1:64} {adv2:32}",
            "{a1:64} {a2:32} {adv2:32} {b1:64}",
            "{adv2:32} {b1:64} {a1:64} {a2:32}",
            "{adv2:32} {b1:64} {a2:32} {a1:64}",
            "{adv2:32} {a1:64} {b1:64} {a2:32}",
            "{adv2:32} {a1:64} {a2:32} {b1:64}",
        ],
    ],
}

_SLOT_RE = re.compile(r"\{(\w+):(\d+)\}")

def bare_noun(word):
    """The noun without its article, as the b1 slot renders it."""
    return word.split(" ", 1)[1] if " " in word else word

def _build_shape(lang, topic, tpl):
    pools = dict(SHARED_POOLS[lang], **TOPIC_WORDS[lang][topic])
    slots, bits = [], 0
    pat, last = "", 0
    for m in _SLOT_RE.finditer(tpl):
        name, cnt = m.group(1), int(m.group(2))
        opts = list(pools[SLOT_POOL[name]][:cnt])
        if len(opts) != cnt or cnt & (cnt - 1):
            raise ValueError(f"word list {name}:{cnt} ({lang}) unusable")
        if name.startswith("b"):
            opts = [w.split(" ", 1)[1] for w in opts]
        if len(set(opts)) != cnt:
            raise ValueError(f"word list {name}:{cnt} ({lang}) has duplicates")
        width = cnt.bit_length() - 1
        slots.append({"opts": opts, "width": width})
        bits += width
        pat += re.escape(tpl[last:m.start()])
        # longest alternative first -> no premature partial match
        alts = sorted(opts, key=len, reverse=True)
        pat += "(" + "|".join(re.escape(w) for w in alts) + ")"
        last = m.end()
    pat += re.escape(tpl[last:])
    return {"tpl": tpl, "slots": slots, "bits": bits,
            "re": re.compile("^" + pat + "$")}

def _build(lang):
    out = []
    for variants in TEMPLATES[lang]:
        n = len(variants)
        if n & (n - 1):
            raise ValueError(f"{lang}: sentence shapes per level must be a power of two")
        sel = n.bit_length() - 1
        # One compiled shape per (variant, topic).  The bit layout is identical
        # across topics, so the topic itself carries no information -- which is
        # exactly why sender and receiver need not agree on the selection.
        shapes = [{tp: _build_shape(lang, tp, v) for tp in TOPIC_ORDER}
                  for v in variants]
        base = {s["bits"] for v in shapes for s in v.values()}
        if len(base) != 1:
            raise ValueError(f"{lang}: sentence shapes of one level must carry "
                             f"the same number of bits, got {sorted(base)}")
        # Every shape has a fixed word count, and all shapes of a level must
        # agree on it -- that is what lets the decoder work on a stream of words
        # instead of on lines.
        toks = {len(_render_shape(s, [0] * s["bits"]).split())
                for v in shapes for s in v.values()}
        if len(toks) != 1:
            raise ValueError(f"{lang}: sentence shapes of one level must have "
                             f"the same word count, got {sorted(toks)}")
        out.append({"shapes": shapes, "sel": sel, "bits": sel + base.pop(),
                    "tokens": toks.pop()})
    return out

def _render_shape(shape, bits):
    idx = 0
    words = []
    for s in shape["slots"]:
        v = 0
        for _ in range(s["width"]):
            v = (v << 1) | bits[idx]
            idx += 1
        words.append(s["opts"][v])
    it = iter(words)
    return _SLOT_RE.sub(lambda m: next(it), shape["tpl"])

def render_sentence(lv, bits, topic="weather"):
    """The leading bits pick the sentence shape, the rest fill its slots.  The
    topic decides only which words are used, never what they mean."""
    sel = 0
    for i in range(lv["sel"]):
        sel = (sel << 1) | bits[i]
    return _render_shape(lv["shapes"][sel][topic], bits[lv["sel"]:])

# A client may prefix a line with a callsign ("KN4CRD: ") or a quote marker
# ("> ").  Cover sentences never contain ":" or ">", so stripping such a prefix
# can never damage a genuine sentence.
_PREFIX_RE = re.compile(r"^[>\s]*(?:[a-z0-9/\-]{1,12}\s*[:>]\s*)?")
_PUNCT_RE = re.compile(r"[.!?,;:\"'()\[\]<>_*]+")

def clean_line(line):
    """Fold away what a transport typically changes: casing, a leading callsign
    or quote marker, punctuation of any kind, and runs of whitespace.  The
    grammar emits none of that, so removing it can never destroy information."""
    s = _PREFIX_RE.sub("", line.strip().lower())
    return re.sub(r"\s+", " ", _PUNCT_RE.sub(" ", s)).strip()

def _match(lv, s, topics):
    """Which shape does this sentence have, and what bits does it carry?  The
    topic comes from the nouns, so any cover decodes regardless of which topics
    its sender had switched on."""
    for k, variant in enumerate(lv["shapes"]):
        for topic in topics:
            m = variant[topic]["re"].match(s)
            if not m:
                continue
            bits = [(k >> b) & 1 for b in range(lv["sel"] - 1, -1, -1)]
            for i, sl in enumerate(variant[topic]["slots"]):
                v = sl["opts"].index(m.group(i + 1))
                for b in range(sl["width"] - 1, -1, -1):
                    bits.append((v >> b) & 1)
            return bits
    return None

def _candidate_topics(lang, words):
    seen = []
    idx = NOUN_TOPIC[lang]
    for w in words:
        tp = idx.get(w)
        if tp is not None and tp not in seen:
            seen.append(tp)
    return seen

def parse_sentence(lv, line, lang):
    s = clean_line(line)
    return _match(lv, s, _candidate_topics(lang, s.split(" ")))

def parse_at(lv, toks, pos, lang):
    """Try to read one sentence out of the word stream starting at pos."""
    n = lv["tokens"]
    if pos + n > len(toks):
        return None
    window = toks[pos:pos + n]
    cands = _candidate_topics(lang, window)
    if not cands:
        return None
    return _match(lv, " ".join(window), cands)

# _build needs render_sentence to measure each template's word count, so the
# grammars are built here rather than next to _build.
def _noun_index(lang):
    """Bare noun -> topic.  Lets the parser go straight to the one topic a
    sentence can possibly belong to instead of trying all six."""
    idx = {}
    for topic in TOPIC_ORDER:
        for w in TOPIC_WORDS[lang][topic]["N"]:
            idx[w.split(" ", 1)[1]] = topic
    return idx

NOUN_TOPIC = {"de": _noun_index("de"), "en": _noun_index("en")}
GRAMMARS = {"de": _build("de"), "en": _build("en")}
LEVELS = range(len(TEMPLATES["de"]))

# --------------------------------------------------------- crypto
MIN_PASS_LEN = 12          # refused outright below this
GOOD_PASS_LEN = 20         # what we actually recommend

def rate_passphrase(p):
    """A deliberately conservative judgement.  No meter can tell whether YOU
    chose a passphrase at random, so this only reports what is checkable:
    length, variety, and whether it looks like a single word.  Returns
    (verdict, note) with verdict in "reject" / "weak" / "ok" / "good"."""
    n = len(p)
    if n < MIN_PASS_LEN:
        return ("reject", f"Too short: {n} of at least {MIN_PASS_LEN} characters. "
                          f"Everything this tool protects rests on this one string.")
    words = [w for w in re.split(r"[^0-9A-Za-z\u00c0-\u024f]+", p) if w]
    uniq = len(set(p.lower()))
    if len(words) <= 1 and n < GOOD_PASS_LEN:
        return ("weak", "Looks like a single word. Four or five unrelated words "
                        "are far harder to guess than one long one.")
    if uniq < 6:
        return ("weak", f"Only {uniq} different characters -- repetition adds "
                        f"length but almost no guesswork.")
    if n < GOOD_PASS_LEN and len(words) < 4:
        return ("ok", f"Usable, but {GOOD_PASS_LEN}+ characters or four or more "
                      f"unrelated words would be markedly better.")
    return ("good", "")

def derive_key(passphrase):
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                              PBKDF2_SALT, PBKDF2_ITERS, 32)
    return {"raw": raw, "aes": AESGCM(raw)}

def encrypt_msg(secret, key):
    """deflate costs 6 bytes of framing, which a short message never earns back
    -- so take whichever is smaller and record which in the manifest."""
    plain = secret.encode("utf-8")
    packed = zlib.compress(plain, 9)
    comp = len(packed) < len(plain)
    iv = os.urandom(12)
    body = key["aes"].encrypt(iv, packed if comp else plain, None)  # ct + 16-byte tag
    return iv + body, comp

def decrypt_msg(ct, key, comp):
    iv, body = ct[:12], ct[12:]
    plain = key["aes"].decrypt(iv, body, None)
    return (zlib.decompress(plain) if comp else plain).decode("utf-8")

def _ks(raw, tag, extra, nbytes):
    """SHA-256 keystream:  seed = raw || tag(2) || extra || counter."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(raw + tag + bytes(extra) + bytes([ctr & 0xff])).digest()
        ctr += 1
    return bytes(out[:nbytes])

def ks_manifest(raw, mnonce, n):
    return _ks(raw, b"SM", mnonce, n)

def ks_block(raw, bnonce, n):
    """Masks the 10-byte block frame.  Deliberately does NOT depend on the
    block index -- that sits inside the frame and is unknown while decoding."""
    return _ks(raw, b"SB", bnonce, n)

def ks_pad(raw, bnonce, idx, n):
    """Padding bits at the end of a sentence run; different per block and
    ignored while decoding."""
    return _ks(raw, b"SP", bytes(bnonce) + bytes([idx & 0xff]), n)

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# --------------------------------------------------------- frames
def build_manifest(raw, K, R, ctlen, bnonce, mnonce, comp):
    plain = bytes([K, R, ((K * CHUNK - ctlen) & 0x07) | (0x08 if comp else 0)]) + bytes(bnonce)
    c = crc16(plain)
    plain += bytes([(c >> 8) & 0xff, c & 0xff])
    return bytes(mnonce) + _xor(plain, ks_manifest(raw, mnonce, len(plain)))

def parse_manifest(raw, buf):
    if len(buf) < MANIFEST_LEN:
        return None
    mnonce = buf[:MNONCE_LEN]
    plain = _xor(buf[MNONCE_LEN:MANIFEST_LEN],
                 ks_manifest(raw, mnonce, MANIFEST_PLAIN))
    if crc16(plain[:-2]) != ((plain[-2] << 8) | plain[-1]):
        return None
    K, R, flags = plain[0], plain[1], plain[2]
    pad, comp = flags & 0x07, bool(flags & 0x08)
    bnonce = plain[3:3 + BNONCE_LEN]
    ctlen = K * CHUNK - pad
    if K == 0 or K + R > MAX_BLOCKS or (flags & 0xf0) or ctlen <= 0:
        return None
    return {"K": K, "R": R, "ctlen": ctlen, "bnonce": bnonce, "comp": comp}

def build_frame(raw, idx, payload, bnonce):
    ck = crc16(bytes([idx]) + payload) & 0xff
    plain = bytes([idx]) + payload + bytes([ck])
    return _xor(plain, ks_block(raw, bnonce, BLOCK_FRAME))

def parse_frame(raw, buf, bnonce):
    plain = _xor(buf[:BLOCK_FRAME], ks_block(raw, bnonce, BLOCK_FRAME))
    idx, payload, ck = plain[0], plain[1:1 + CHUNK], plain[-1]
    if (crc16(bytes([idx]) + payload) & 0xff) != ck:
        return None
    return idx, payload

def render_run(lv, frame, nbits, pad, topics):
    """Bit field -> sentences; fill the last sentence's spare capacity from pad.
    A topic is drawn per sentence, so a cover wanders between subjects the way
    real chatter does instead of hammering one."""
    bits = bytes_to_bits(frame)[:nbits]
    n = math.ceil(nbits / lv["bits"])
    need = n * lv["bits"] - nbits
    if need > 0:
        bits = bits + bytes_to_bits(pad)[:need]
    return [render_sentence(lv, bits[i * lv["bits"]:(i + 1) * lv["bits"]],
                            topics[secrets.randbelow(len(topics))])
            for i in range(n)]

def sentences_for(lv, nbits):
    return math.ceil(nbits / lv["bits"])

# --------------------------------------------------------- encode / decode
def apply_profile(txt, profile):
    """js8call = upper case (JS8Call's efficient character set), plain = lower
    case.  Casing carries no data; the decoder lower-cases everything anyway."""
    return txt.upper() if profile == "js8call" else txt.lower()

def encode(secret, key, lang="de", profile="plain", level=1, parity=2, topics=None):
    """`topics` only decides which words the cover is built from.  It carries no
    data, so the receiver does not need to know or match it."""
    raw = key["raw"]
    lv = GRAMMARS[lang][level]
    topics = list(topics or DEFAULT_TOPICS)
    unknown = [t for t in topics if t not in TOPIC_ORDER]
    if unknown:
        raise ValueError(f"unknown topic(s): {', '.join(unknown)}")
    if not topics:
        raise ValueError("at least one topic must be selected")
    ct, comp = encrypt_msg(secret, key)
    ctlen = len(ct)
    padded = ct + b"\x00" * ((-ctlen) % CHUNK)
    K = len(padded) // CHUNK
    if K > MAX_BLOCKS:
        raise ValueError(f"Message too long -- {K} data blocks, the limit is "
                         f"{MAX_BLOCKS} (about {MAX_BLOCKS * CHUNK} bytes of ciphertext).")
    data = [padded[i * CHUNK:(i + 1) * CHUNK] for i in range(K)]
    R = min(parity, max(0, MAX_BLOCKS - K))
    parity_blocks = []
    if R > 0:
        P = cauchy(R, K)
        for r in range(R):
            pb = bytearray(CHUNK)
            for j in range(CHUNK):
                acc = 0
                for i in range(K):
                    acc ^= gmul(P[r][i], data[i][j])
                pb[j] = acc
            parity_blocks.append(bytes(pb))
    allb = data + parity_blocks
    tot = len(allb)

    bnonce = os.urandom(BNONCE_LEN)
    pad_bytes = math.ceil(lv["bits"] / 8) + 1

    def manifest_section():
        mnonce = os.urandom(MNONCE_LEN)
        buf = build_manifest(raw, K, R, ctlen, bnonce, mnonce, comp)
        pad = ks_pad(raw, bnonce, 0xff, pad_bytes)
        return {"lines": render_run(lv, buf, MANIFEST_BITS, pad, topics)}

    sections = [manifest_section()]
    for i in range(tot):
        buf = build_frame(raw, i, allb[i], bnonce)
        pad = ks_pad(raw, bnonce, i, pad_bytes)
        sections.append({"lines": render_run(lv, buf, FRAME_BITS, pad, topics), "block": i})
    sections.append(manifest_section())

    return {"sections": sections, "K": K, "R": R, "tot": tot, "ctlen": ctlen,
            "level": level, "lang": lang, "profile": profile, "topics": topics,
            "comp": comp}

def cover_to_text(enc, sections=None):
    """Cover as text -- nothing but carrier sentences, no framing lines of any
    kind.  The profile only decides the casing: js8call sends upper case (that
    is the character set JS8Call transmits most efficiently), plain sends lower
    case so it reads like an ordinary chat message.  Never put a callsign in
    here yourself: JS8Call prefixes your own callsign automatically, and
    transmitting one that is not yours is illegal."""
    parts = []
    for s in (sections if sections is not None else enc["sections"]):
        parts += [apply_profile(l, enc["profile"]) for l in s["lines"]]
    return "\n".join(parts)

def _tokens(cover_text):
    """The whole cover as one stream of words.  Line breaks carry no
    information, so a transport that reflows, wraps or joins lines cannot
    hurt -- the sentences are recovered from the word sequence alone."""
    toks = []
    for l in cover_text.splitlines():
        if not l.strip():
            continue
        s = clean_line(l)
        if s:
            toks.extend(s.split(" "))
    return toks

def _foreign_chars(cover_text):
    """Characters the grammar never produces.  Their presence means the text was
    altered on the way -- the most common reason decoding fails, and one that
    otherwise looks exactly like a wrong passphrase."""
    seen = set()
    for l in cover_text.splitlines():
        if not l.strip():
            continue
        s = _PREFIX_RE.sub("", l.strip().lower())
        seen.update(c for c in s if not (c == " " or ("a" <= c <= "z")))
    return sorted(seen)

def _read_run(lv, toks, pos, n_sent, lang):
    """Read n_sent consecutive sentences from the word stream at pos."""
    bits = []
    step = lv["tokens"]
    for s in range(n_sent):
        pb = parse_at(lv, toks, pos + s * step, lang)
        if pb is None:
            return None
        bits += pb
    return bits

def _find_manifest(raw, toks):
    """Tries every (language, level) and slides a window over the word stream;
    the manifest CRC16 decides.  Returns the manifest fields, the language, the
    level and the word ranges it occupies.  Sliding by a single word is what
    lets the decoder re-align after damage of any kind."""
    n = len(toks)
    for lang in ("de", "en"):
        for level in LEVELS:
            lv = GRAMMARS[lang][level]
            n_sent = sentences_for(lv, MANIFEST_BITS)
            span = n_sent * lv["tokens"]
            hit, spans = None, []
            i = 0
            while i + span <= n:
                bits = _read_run(lv, toks, i, n_sent, lang)
                if bits is not None:
                    man = parse_manifest(raw, bits_to_bytes(bits[:MANIFEST_BITS]))
                    if man is not None:
                        if hit is None:
                            hit = man
                        spans.append((i, i + span))
                        i += span
                        continue
                i += 1
            if hit is not None:
                return hit, lang, level, spans
    return None, None, None, []

def decode(cover_text, key):
    raw = key["raw"]
    toks = _tokens(cover_text)
    foreign = _foreign_chars(cover_text)
    warning = None
    if foreign:
        warning = ("The text contains characters this tool never produces ("
                   + " ".join(foreign) + ") -- something on the transport path "
                   "altered it. Trailing punctuation is tolerated; anything else "
                   "costs the affected block.")
    man, lang, level, spans = _find_manifest(raw, toks)
    if man is None:
        if foreign:
            return {"ok": False, "warning": warning,
                    "error": "No valid manifest found. The text contains characters "
                             "this tool never produces (" + " ".join(foreign) + "), so "
                             "the transport path most likely altered it -- the "
                             "passphrase may well be fine."}
        return {"ok": False, "error": "No valid manifest found -- wrong passphrase, "
                                      "or this is not cover text."}
    K, R, ctlen, bnonce = man["K"], man["R"], man["ctlen"], man["bnonce"]
    comp = man["comp"]
    tot = K + R
    lv = GRAMMARS[lang][level]
    n_sent = sentences_for(lv, FRAME_BITS)
    span = n_sent * lv["tokens"]

    blocked = set()
    for a, b in spans:
        blocked.update(range(a, b))

    n = len(toks)
    found = {}
    i = 0
    while i + span <= n:
        if any(x in blocked for x in range(i, i + span)):
            i += 1
            continue
        bits = _read_run(lv, toks, i, n_sent, lang)
        if bits is not None:
            fr = parse_frame(raw, bits_to_bytes(bits[:FRAME_BITS]), bnonce)
            if fr is not None and fr[0] < tot and fr[0] not in found:
                found[fr[0]] = fr[1]
                i += span
                continue
        i += 1

    data_missing = [d for d in range(K) if d not in found]
    present = sorted(found.keys())

    if not data_missing:
        data_blocks = [found[d] for d in range(K)]
        recovered = False
    elif len(present) >= K:
        P = cauchy(R, K)
        surv = present[:K]
        A = [_unit(idx, K) if idx < K else list(P[idx - K]) for idx in surv]
        Ainv = mat_inv(A, K)
        if Ainv is None:
            return {"ok": False, "missing": data_missing, "tot": tot, "K": K,
                    "recovered": False, "error": "Reconstruction failed."}
        data_blocks = [bytearray(CHUNK) for _ in range(K)]
        for j in range(CHUNK):
            rhs = [found[idx][j] for idx in surv]
            for d in range(K):
                acc = 0
                for m in range(K):
                    acc ^= gmul(Ainv[d][m], rhs[m])
                data_blocks[d][j] = acc
        data_blocks = [bytes(b) for b in data_blocks]
        recovered = True
    else:
        return {"ok": False, "missing": data_missing, "tot": tot, "K": K,
                "recovered": False, "warning": warning}

    ct = b"".join(data_blocks)[:ctlen]
    try:
        msg = decrypt_msg(ct, key, comp)
        return {"ok": True, "message": msg, "tot": tot, "K": K,
                "recovered": recovered, "R": R, "lang": lang, "level": level,
                "warning": warning}
    except Exception:
        return {"ok": False, "tot": tot, "K": K, "warning": warning,
                "error": "Decryption failed -- wrong passphrase, or too many "
                         "damaged blocks."}

def nack_string(res):
    if not res.get("missing"):
        return None
    return ", ".join(str(i) for i in res["missing"]) + f" of {res['tot']}"

# --------------------------------------------------------- selftest
def _selftest():
    key = derive_key("test-passphrase")
    ok_all = True
    for lang, level, par, profile in [("de", 1, 2, "js8call"), ("en", 0, 2, "plain"),
                                      ("de", 3, 1, "plain"), ("en", 2, 2, "js8call")]:
        secret = f"Meet Sunday 6pm at the old harbour -- {lang}/{level}"
        enc = encode(secret, key, lang=lang, profile=profile, level=level, parity=par)
        cover = cover_to_text(enc)
        r0 = decode(cover, key)
        clean = r0.get("ok") and r0.get("message") == secret
        det = (r0.get("lang") == lang and r0.get("level") == level)
        print(f"[{lang} L{level} P{par} {profile}] clean: {r0.get('ok')} "
              f"-> {'MATCH' if clean else 'MISMATCH'}"
              f"  detected: {r0.get('lang')}/L{r0.get('level')} {'OK' if det else 'WRONG'}")
        ok_all &= bool(clean and det)

        # drop par data blocks -> recovered via parity, no resend needed
        keep = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par]
        r1 = decode(cover_to_text(enc, keep), key)
        via = r1.get("ok") and r1.get("recovered") and r1.get("message") == secret
        print(f"   {par} blocks dropped -> ok: {r1.get('ok')} via_parity: {r1.get('recovered')} "
              f"msg: {'MATCH' if via else r1.get('error') or 'MISMATCH'}")
        ok_all &= bool(via)

        # drop par+1 -> NACK
        keep2 = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par + 1]
        r2 = decode(cover_to_text(enc, keep2), key)
        print(f"   {par+1} blocks dropped -> ok: {r2.get('ok')} nack: {nack_string(r2)}")
        ok_all &= (not r2.get("ok")) and bool(r2.get("missing"))

        # drop the leading manifest -> the trailing one must take over
        keep3 = enc["sections"][1:]
        r3 = decode(cover_to_text(enc, keep3), key)
        man_ok = r3.get("ok") and r3.get("message") == secret
        print(f"   leading manifest dropped -> ok: {r3.get('ok')} "
              f"msg: {'MATCH' if man_ok else r3.get('error') or 'MISMATCH'}")
        ok_all &= bool(man_ok)

        # delete a single sentence in the middle -> resync + erasure
        raw_lines = cover_to_text(enc).split("\n")
        cut = len(raw_lines) // 2
        del raw_lines[cut]
        r4 = decode("\n".join(raw_lines), key)
        print(f"   1 sentence deleted -> ok: {r4.get('ok')} "
              f"msg: {'MATCH' if r4.get('message') == secret else r4.get('error') or 'NACK'}")
        ok_all &= bool(r4.get("ok") and r4.get("message") == secret)

    # a mangled transport: callsign prefix, trailing punctuation, doubled spaces
    enc = encode("Meet at six", key, lang="en", level=2, parity=2)
    mangled = "\n".join("KN4CRD: " + l.replace(" ", "  ") + "!"
                        for l in cover_to_text(enc).split("\n"))
    r6 = decode(mangled, key)
    print(f"[mangled transport] ok: {r6.get('ok')} "
          f"msg: {'MATCH' if r6.get('message') == 'Meet at six' else 'MISMATCH'} "
          f"warned: {bool(r6.get('warning'))}")
    ok_all &= bool(r6.get("ok") and r6.get("message") == "Meet at six" and r6.get("warning"))

    # Every sentence must match exactly one (shape, topic), or decoding is a
    # coin flip.  This is the rule the whole topic feature rests on.
    import random
    amb = []
    for lang in ("de", "en"):
        for level, lv in enumerate(GRAMMARS[lang]):
            for topic in TOPIC_ORDER:
                for _ in range(120):
                    bits = [random.randint(0, 1) for _ in range(lv["bits"])]
                    s = render_sentence(lv, bits, topic)
                    hits = sum(1 for v in lv["shapes"] for tp in TOPIC_ORDER
                               if v[tp]["re"].match(s))
                    if hits != 1:
                        amb.append(f"{lang} L{level}/{topic}: {s!r} matched {hits}")
                        break
                    if parse_sentence(lv, s, lang) != bits:
                        amb.append(f"{lang} L{level}/{topic}: {s!r} lost its bits")
                        break
                if amb:
                    break
    print(f"[sentence shapes] unambiguous across all topics: "
          f"{'yes' if not amb else 'NO -- ' + '; '.join(amb)}")
    ok_all &= not amb

    # A receiver must not need the sender's topic selection.
    mixed = encode("Meet at six", key, lang="en", level=1, parity=2,
                   topics=["weather", "home"])
    r_mix = decode(cover_to_text(mixed), key)
    afu = encode("Meet at six", key, lang="en", level=1, parity=2, topics=AFU_TOPICS)
    r_afu = decode(cover_to_text(afu), key)
    both = r_mix.get("message") == "Meet at six" and r_afu.get("message") == "Meet at six"
    print(f"[topic independence] a cover decodes whatever topics its sender used: "
          f"{'yes' if both else 'NO'}")
    ok_all &= both

    # deflate must never make the ciphertext bigger than the raw message
    for probe in ("hi", "Meet at six", "Treffen Sonntag 18 Uhr am alten Hafen",
                  "Treffen Sonntag 18 Uhr am alten Hafen. " * 20):
        e = encode(probe, key, lang="en", level=1, parity=2)
        r = decode(cover_to_text(e), key)
        if r.get("message") != probe:
            print(f"[compression] FAILED for {len(probe)} chars")
            ok_all = False
            break
    else:
        print("[compression] raw/deflate choice round-trips at every length")

    # a transport that reflows, joins or wraps lines must not matter at all
    import textwrap
    flat = " ".join(cover_to_text(enc).split("\n"))
    reflow = {"one line": flat,
              "wrapped at 40": textwrap.fill(flat, 40),
              "wrapped at 200": textwrap.fill(flat, 200),
              "blank lines": "\n\n".join(textwrap.wrap(flat, 120))}
    bad = [n for n, txt in reflow.items()
           if decode(txt, key).get("message") != "Meet at six"]
    print(f"[reflowed lines] {len(reflow) - len(bad)}/{len(reflow)} ok"
          + (f" -- FAILED: {bad}" if bad else ""))
    ok_all &= not bad

    # a clean cover must NOT be flagged
    r7 = decode(cover_to_text(enc), key)
    print(f"[clean cover] ok: {r7.get('ok')} warned: {bool(r7.get('warning'))} "
          f"-> {'OK' if r7.get('ok') and not r7.get('warning') else 'FAILURE'}")
    ok_all &= bool(r7.get("ok") and not r7.get("warning"))

    # a wrong passphrase must not get through
    enc = encode("secret", key, lang="de", level=1, parity=2)
    r5 = decode(cover_to_text(enc), derive_key("wrong"))
    print(f"[wrong passphrase] ok: {r5.get('ok')} -> {'correctly rejected' if not r5.get('ok') else 'FAILURE'}")
    ok_all &= (not r5.get("ok"))

    print("selftest done:", "ALL GREEN" if ok_all else "FAILURE")
    return ok_all

# --------------------------------------------------------- CLI
def _main():
    ap = argparse.ArgumentParser(description="StegoComm v4 -- byte-compatible with cover_studio.html")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encode", help="plaintext -> cover (stdout)")
    pe.add_argument("message", nargs="*", help="message (otherwise read from stdin)")
    pe.add_argument("--pass", dest="passphrase", required=True)
    pe.add_argument("--lang", choices=["de", "en"], default="de")
    pe.add_argument("--level", type=int, default=1, choices=[0, 1, 2, 3],
                    help="0=very believable ... 3=very terse")
    pe.add_argument("--parity", type=int, default=2)
    pe.add_argument("--allow-weak-pass", action="store_true",
                    help="encode even with a passphrase below the minimum length")
    pe.add_argument("--topics", default=",".join(DEFAULT_TOPICS),
                    metavar="A,B,...",
                    help="cover vocabulary: " + ", ".join(TOPIC_ORDER)
                         + " (default: everything but tech)")
    pe.add_argument("--afu", action="store_true",
                    help="amateur-radio mode: use the tech vocabulary only")
    pe.add_argument("--profile", choices=["js8call", "plain"], default="plain",
                    help="plain=lower case (default), js8call=upper case")

    pd = sub.add_parser("decode", help="cover (stdin) -> plaintext")
    pd.add_argument("--pass", dest="passphrase", required=True)

    sub.add_parser("selftest", help="check round-trip + parity + NACK")

    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(0 if _selftest() else 1)

    if args.cmd == "encode":
        verdict, note = rate_passphrase(args.passphrase)
        if verdict == "reject" and not args.allow_weak_pass:
            print("REFUSED: " + note, file=sys.stderr)
            print("A good passphrase is four or five unrelated words, e.g. "
                  "\"harbour-lantern-quiet-seven\". Pass --allow-weak-pass to "
                  "override.", file=sys.stderr)
            sys.exit(3)
        if note:
            print("WARNING: " + note, file=sys.stderr)

    key = derive_key(args.passphrase)
    if args.cmd == "encode":
        msg = " ".join(args.message) if args.message else sys.stdin.read().rstrip("\n")
        topics = AFU_TOPICS if args.afu else [t.strip() for t in args.topics.split(",") if t.strip()]
        enc = encode(msg, key, lang=args.lang, profile=args.profile,
                     level=args.level, parity=args.parity, topics=topics)
        print(cover_to_text(enc))
    elif args.cmd == "decode":
        res = decode(sys.stdin.read(), key)
        if res.get("warning"):
            print("WARNING: " + res["warning"], file=sys.stderr)
        if res.get("ok"):
            tag = " [recovered via parity]" if res.get("recovered") else ""
            print(res["message"] + tag)
        elif res.get("missing"):
            print("NACK -- missing data blocks: " + (nack_string(res) or ""), file=sys.stderr)
            sys.exit(2)
        else:
            print("ERROR: " + res.get("error", "unknown"), file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    _main()
