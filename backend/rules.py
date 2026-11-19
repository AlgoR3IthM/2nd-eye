"""Signal A: Romanian intent rules for the 13 official red flags.

detect(text, ctx) -> [{"code": "RF_...", "start": int, "end": int}]
ctx = {channel, known_contact, sender, n, prior_flags}

Text is folded (lowercase, no diacritics, s/ş/ș, t/ţ/ț, dash and quote variants unified) one character to one
character, so every span found on the folded text is a valid span on the original text.
Rules look for intent (a request, a claim, a threat), not bare keywords, and skip protective sentences
("nu comunicați acest cod nimănui"). Never raises.
"""
import re
import unicodedata

MAX_LEN = 20000

_CHARMAP = {
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
    "‘": "'", "’": "'", "‚": "'", "‛": "'", "`": "'", "´": "'",
    "“": '"', "”": '"', "„": '"', "«": '"', "»": '"',
    " ": " ", " ": " ", " ": " ", "​": " ", "\t": " ",
    "ș": "s", "ş": "s", "Ș": "s", "Ş": "s",
    "ț": "t", "ţ": "t", "Ț": "t", "Ţ": "t",
}


def fold(text):
    """lowercase + strip diacritics, strictly one char -> one char."""
    out = []
    for ch in text or "":
        m = _CHARMAP.get(ch)
        if m is None:
            d = unicodedata.normalize("NFKD", ch)
            b = "".join(c for c in d if not unicodedata.combining(c))
            b = b.lower() if b else ch.lower()
            m = b[:1] if b else " "
            if not m:
                m = " "
        out.append(m)
    return "".join(out)


# ----------------------------------------------------------------------------------------------- obfuscation
# normalise() undoes common evasions on the folded text and keeps, for every output character, the span of the
# original text it came from, so spans found on the normalised text map back to valid highlights.
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "i"}
_RX_SPACED = re.compile(r"(?<![a-z0-9])[a-z](?![a-z])(?:[ .\-_*]{1,3}[a-z](?![a-z])){2,}")
_RX_LEET = re.compile(r"(?<=[a-z])[013457@$](?=[a-z])|(?<![a-z0-9@.])@(?=[a-z]{2})(?![a-z0-9-]*\.[a-z]{2,})")
_RX_REPEAT = re.compile(r"([a-z])\1{2,}|([aou])\2(?![a-z])")
_RX_MONEY_EMOJI = re.compile("[\U0001F4B0\U0001F4B5\U0001F4B6\U0001F4B7\U0001F4B8\U0001F911\U0001F3E6]")
_RX_EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿️‍]")
_ABBR = {"nev": "nevoie", "trb": "trebuie", "trebe": "trebuie", "tre": "trebuie", "pt": "pentru", "ptr": "pentru",
         "rpd": "repede", "pls": "te rog", "plz": "te rog", "pliz": "te rog", "acm": "acum", "imd": "imediat",
         "tlf": "telefon", "msj": "mesaj", "dc": "de ce"}
_RX_ABBR = re.compile(r"\b(?:" + "|".join(sorted(_ABBR, key=len, reverse=True)) + r")\b")


def _sub(cells, rx, repl):
    s = "".join(c[0] for c in cells)
    out, last = [], 0
    for m in rx.finditer(s):
        if m.start() < last or m.end() == m.start():
            continue
        out.extend(cells[last:m.start()])
        r = repl(m)
        a, b = cells[m.start()][1], cells[m.end() - 1][2]
        out.extend((ch, a, b) for ch in r)
        last = m.end()
    out.extend(cells[last:])
    return out


def normalise(ft):
    """folded text -> (normalised text, [(orig_start, orig_end)] per normalised char)."""
    cells = [(ch, i, i + 1) for i, ch in enumerate(ft)]
    try:
        cells = _sub(cells, _RX_MONEY_EMOJI, lambda m: " bani ")
        cells = _sub(cells, _RX_EMOJI, lambda m: " ")
        cells = _sub(cells, _RX_LEET, lambda m: _LEET.get(m.group(0), m.group(0)))
        cells = _sub(cells, _RX_SPACED, lambda m: re.sub(r"[^a-z]", "", m.group(0)))
        cells = _sub(cells, _RX_REPEAT, lambda m: m.group(1) or m.group(2))
        cells = _sub(cells, _RX_ABBR, lambda m: _ABBR.get(m.group(0), m.group(0)))
    except Exception:
        cells = [(ch, i, i + 1) for i, ch in enumerate(ft)]
    return "".join(c[0] for c in cells), [(c[1], c[2]) for c in cells]


def norm_text(text):
    """fold + normalise, for callers that only need the text (scam type)."""
    return normalise(fold(text or ""))[0]


# ----------------------------------------------------------------------------------------------- helpers

def _sentences(ft):
    """[(start, end)] of sentences on folded text."""
    spans, start = [], 0
    for m in re.finditer(r"[!?\n]+|\.(?=\s|$)(?<!\bdvs\.)(?<!\bnr\.)(?<!\bstr\.)(?<!\bdl\.)(?<!\bdna\.)", ft):
        spans.append((start, m.end()))
        start = m.end()
    if start < len(ft):
        spans.append((start, len(ft)))
    return spans or [(0, len(ft))]


def _sent_of(sents, pos):
    for a, b in sents:
        if a <= pos < b:
            return a, b
    return 0, 0


_NEG_BEFORE = re.compile(r"(?:\bnu\b|\bniciodata\b|\bnici\b|\bnu-)[\s\-]*(?:[\w']+[\s\-]+){0,3}$")
_PROTECTIVE = re.compile(
    r"\bnimanui\b|\bniciodata\b|\bnu (?:le |il |o |ii |va )?(?:comunicati|comunica|dati|da|spuneti|spune|trimiteti|trimite|"
    r"divulgati|instalati|oferiti|introduceti|furnizati|transmiteti|raspundeti)\b|\bnu (?:va )?(?:vom|va|vor) cere\b|"
    r"\bnu (?:cerem|solicitam|cere|solicita)\b|\bnu partaja\w*")


def _neg(ft, pos, sent_start):
    w = ft[max(sent_start, pos - 30):pos]
    return bool(_NEG_BEFORE.search(w))


def _protective(ft, sents, pos):
    a, b = _sent_of(sents, pos)
    return bool(_PROTECTIVE.search(ft[a:b]))


def _finditer(rx, ft):
    try:
        return list(rx.finditer(ft))
    except Exception:
        return []


def _R(p):
    return re.compile(p)


# ----------------------------------------------------------------------------------------------- vocab

REQ_VERB = (r"(?:complet(?:ati|eaza|ezi|a)\b|introdu(?:ceti|ce|ci)?\b|trimite\w*|trimiti|spune\w*|spui|dati|da-mi|da-ne|da mi|comunica\w*|furniz\w*|"
            r"confirma\w*|reconfirma\w*|scrie\w*|citi\w*|dicta\w*|fotografia\w*|face\w* (?:o )?poza|avem nevoie|am nevoie|"
            r"ne trebuie|imi trebuie|actualiz\w*|verific\w*|valid\w*|intrati|intra|loga\w*|logheaza\w*|conect\w*|"
            r"accesa\w*|acceseaza\w*|autentific\w*|transmite\w*|ne puteti da|imi puteti da|mi le|ni le|sa ne dati|sa imi dati|sa-mi dati)")

ORG = (r"(?:banca \w+|banc(?:a|ii) (?:dumneavoastra|dvs|ta)|bancadunarea|banca transilvania|\bbcr\b|\bbrd\b|\bing bank\b|"
       r"raiffeisen|\bcec bank\b|revolut|unicredit|posta romana|fan ?courier|cargus|sameday|\bdhl\b|\bdpd\b|\bgls\b|"
       r"\bemag\b|\bolx\b|netflix|microsoft|windows|\bapple\b|\bgoogle\b|"
       r"departamentul (?:de )?(?:securitate|fraud\w*|tehnic|antifrauda|clienti|relatii)|serviciul (?:de )?(?:clienti|tehnic|"
       r"securitate|relatii)\w*|suport(?:ul)? (?:tehnic|clienti|pentru clienti)|asistenta tehnica|centrul de securitate|"
       r"politi(?:a|ei|e)\b|politist\w*|agent(?:ul)? de politie|procuror\w*|parchet\w*|\bdiicot\b|\bdna\b|\banaf\b|fiscul|"
       r"casa (?:nationala )?de pensii|casei (?:nationale )?de pensii|\bcnas\b|\bcnpp\b|casa (?:judeteana )?de (?:asigurari de )?sanatate|"
       r"primari(?:a|ei)\b|ministerul \w+|guvernul\w*|instant(?:a|ei)\b|judecatori\w*|executor\w*(?: judecatoresc)?|"
       r"autoritatea \w+|\banpc\b|\benel\b|\be-?on\b|\bengie\b|electrica\b|\bdigi\b|\borange\b|vodafone|telekom|"
       r"curier ?expres|piata ?mea|mega ?shop)")

# ----------------------------------------------------------------------------------------------- rules

NUMW = r"(?:doua|doi|trei|patru|cinci|sase|sapte|opt|noua|zece|\w+sprezece|\w+zeci)"
CODE_WORD = (r"(?:codul(?! numeric| postal| de bare| fiscal| iban| de client| de abonat| de comanda| de la (?:interfon|usa|poarta))|"
             r"codurile|cod(?! numeric| postal| de bare| fiscal)|coduri|otp|parola unica|cifrele|caracterele|"
             r"(?:cele )?(?:\d+|" + NUMW + r") (?:cifre|caractere)|codul primit)")
CODE_VERB = (r"(?:trimite|trimiteti|trimiti|retrimite\w*|spune|spuneti|spui|zi|da|dati|comunica|comunicati|citeste|cititi|"
             r"citi|dicteaza|dictati|dictezi|transmite|transmiteti|redirectiona\w*|forward\w*|scrie|scrieti|scrii)")
# a code for a door, gate or wifi is not a one-time code
RX_CODE_HARMLESS = _R(r"\b(?:interfon\w*|usa|usii|poarta|portii|lacat\w*|wi-?fi|alarma|seif\w*|cutia postala|parcar\w*|scara|scarii|blocul|blocului)\b")
RX_CODE = [
    _R(r"\b" + CODE_VERB + r"\s*-?\s*(?:mi|ne|mi-l|ni-l|-mi|-ne)?\b[^.!?\n]{0,40}\b" + CODE_WORD + r"\b"),
    _R(r"\b" + CODE_WORD + r"\b[^.!?\n]{0,50}\b" + CODE_VERB + r"\s*-\s*(?:mi|ne)\b"),
    _R(r"\b(?:care|ce)\s+(?:e|este)\s+codul\b|\bam nevoie de (?:codul|cod|cifrele)\b|\bce cod (?:ai|ati) primit\b"),
    _R(r"\bintrodu\w*\s+(?:si\s+)?" + CODE_WORD + r"\b[^.!?\n]{0,40}\b(?:aici|pe (?:site|pagina|link)|in (?:link|pagina|formular)|la adresa)\b"),
]
RX_CODE_PRON = _R(r"\b(?:mi|ni)\s*-?\s*(?:l|le)\s+(?:\w+\s+){0,2}(?:trimite|trimiti|trimiteti|da|dai|dati|spune|spui|spuneti|citi|cititi|"
                  r"citesti|dicta|dictati|dictezi|zici|confirmi|confirmati|transmite|transmiteti|redirectiona\w*|retrimite\w*|scrie|scrii|scrieti)\b"
                  r"|\b(?:cititi|spuneti|dictati|trimiteti|citeste|spune|trimite)\s*-\s*mi\s*-?\s*l\b")
RX_CODE_CTX = _R(r"\bcod\w*|\botp\b|\bcifre\w*|\bcaracter\w*|\bsms\w*")
# indirect phrasings: "a venit un cod ... zi-mi-l", "scrie-l aici", "ce scrie in sms?", "care sunt cifrele?"
_CLITIC_VERB = (r"(?:zi|zici|spune|spuneti|spui|da|dai|dati|trimite|trimiteti|trimiti|scrie|scrieti|scrii|citeste|cititi|citesti|"
                r"dicteaza|dictati|dictezi|confirma|confirmati|confirmi|transmite|transmiteti|redirectiona\w*|retrimite\w*)")
RX_CODE_PRON2 = _R(r"\b" + _CLITIC_VERB + r"\s*-\s*(?:mi|ne)\s*-?\s*(?:l|le)\b"
                   r"|\b" + _CLITIC_VERB + r"\s*-\s*(?:l|le)\s+(?:aici|repede|imediat|acum|mie|noua|la mine|pe chat|in chat|pe whatsapp|"
                   r"pe telegram|prin raspuns|ca raspuns|inapoi|operatorului|la telefon)\b"
                   # "codul ... il trimiti aici", "cifrele ... mi le dictezi"
                   r"|(?<!nu )\b(?:il|l|o|le)\s+(?:trimiti|trimiteti|dai|dati|spui|spuneti|scrii|scrieti|zici|dictezi|dictati|citesti|cititi|"
                   r"confirmi|confirmati)\s+(?:\w+\s+){0,1}(?:aici|mie|noua|repede|acum|te rog|va rog|inapoi|pe chat|pe whatsapp|operatorului)\b"
                   # "confirmati-ne cifrele", "trimite-mi poza cu mesajul / codul"
                   r"|\bconfirma\w*\s*-?\s*(?:ne|mi)\b[^.!?\n]{0,30}\b(?:cod\w*|cifre\w*|caracter\w*|otp)\b"
                   r"|\b(?:trimite\w*|trimiti|fa|faci|faceti)\b[^.!?\n]{0,20}\b(?:poza|o poza|captura|screenshot|print ?screen)\b[^.!?\n]{0,15}"
                   r"\b(?:mesaj\w*|sms\w*|cod\w*|ecran\w*|cifre\w*)\b")
# a bare "Codul?" / "codul pls" as the whole message
RX_CODE_SHORT = _R(r"^\W*(?:si\s+)?(?:codul|codu|otp-?ul|otp|cifrele)\b\s*(?:te rog|please|repede|acum|urgent|rapid|imediat|\?|!|\s)*\W*$")
RX_CODE_ASK = _R(r"\bce (?:scrie|zice|spune|arata|apare)\b[^.!?\n]{0,25}\b(?:sms\w*|mesaj\w*|acolo|telefon\w*|ecran\w*|pe el|in el)\b"
                 r"|\b(?:care|ce)\s+(?:sunt\s+)?(?:cele\s+)?(?:\d+\s+)?cifre\w*\b")

REMOTE_TOOLS = (r"any ?d\w{0,2}sk|team ?v\w{0,2}we?r|rust ?desk|quick ?support|ultra ?viewer|\bsupremo\b|air ?droid|alpemix|ammyy|"
                r"splashtop|chrome remote desktop|remote desktop|\bvnc\b|ammy admin|zoho assist|logmein")
RX_REMOTE = [
    _R(r"(?:" + REMOTE_TOOLS + r")"),
    _R(r"\b(?:instala\w*|descarca\w*|deschide\w*)\b[^.!?\n]{0,50}\b(?:aplicati\w*|program\w*)\b[^.!?\n]{0,60}\b(?:de la distanta|control\w*|acces\w*)\b"),
    _R(r"\b(?:acces\w*|control\w*|conecta\w*|ajuta\w*|prelua\w*|preia\w*|intra\w*|vedem|verificam)\b[^.!?\n]{0,30}\bde la distanta\b"),
    _R(r"\bpartaj\w* (?:de )?ecran\w*|\bshare ?screen\b|\bscreen ?shar\w*"),
    # remote control described, not named: "instalati aplicatia pe care v-o trimit ... sa vad ecranul / apasati Permite"
    _R(r"\b(?:instala\w*|descarca\w*|cauta\w*)\b[^.!?\n]{0,50}\b(?:aplicati\w*|program\w*)\b[^.!?\n]{0,80}"
       r"\b(?:ce se (?:intampla|vede) pe ecran|ecranul (?:dvs|dumneavoastra|tau|telefonului|calculatorului)|"
       r"sa (?:vad|vedem|intru|intram|ma conectez|ne conectam|preiau|controlez)|apasati (?:pe )?(?:permite|accept\w*|allow)|"
       r"dati-?mi acces|da-?mi acces|sa va ajut eu)\b"),
    _R(r"\b(?:lasati|lasa|permiteti|permite)\s*-?\s*(?:ma|ne)\b[^.!?\n]{0,15}\b(?:sa )?(?:intru|intram|ma conectez|ne conectam|preiau|controlez)\b"
       r"[^.!?\n]{0,25}\b(?:telefon\w*|calculator\w*|laptop\w*|pc\w*|ecran\w*|dispozitiv\w*|tableta\w*)"),
    _R(r"\b(?:dati|da|oferiti|acordati)\s*-?\s*(?:mi|ne)\s+acces(?:ul)?\b(?! la (?:casa|curte|apartament|scara|bloc))"),
]

DATA_NOUN = _R(
    r"\bdatele (?:de pe )?card\w*|\bdate(?:le)? (?:de )?card\w*|\bdatele bancare\b|\bdate bancare\b|\bnumar(?:ul)? (?:de )?card\w*|"
    r"\bnr\.? (?:de )?card\w*|\b(?:detalii\w*|informatii\w*) (?:de |ale |despre )?(?:card\w*|bancar\w*)|"
    r"\bdatele (?:dvs\.? |dumneavoastra )?(?:de )?(?:card\w*|bancare)|"
    r"\b(?:introduceti|completati|trimiteti|scrieti|confirmati|furnizati) (?:si )?cardul\b|\bcvv\w*|\bcvc\b|\bcod(?:ul)? (?:de securitate|de pe spate\w*|cvv)|\bcodul pin\b|\bpin(?:-?ul)?\b|"
    r"\bparol(?:a|ele|ei)\b|\bcnp(?:-?ul)?\b|\bcod(?:ul)? numeric personal\b|\bseria (?:si numarul )?(?:de )?(?:buletin\w*|ci|cartii)\b|"
    r"\b(?:poza|poze|fotografi\w*|copie|copia|scan\w*)\b(?: (?:fata-verso|fata|verso|clara|buna|rapida|ambele parti))? "
    r"(?:cu |a |dupa |de pe |la |la |in )?(?:buletin\w*|cartea de identitate|actul de identitate|"
    r"ci\b|pasaport\w*|card\w*)|\bdate(?:le)? de (?:logare|autentificare|acces|conectare)\b|\b(?:user|utilizator)\w* si parol\w*|"
    r"\bdata (?:de )?expir\w*|\bdatele (?:personale|dumneavoastra personale|de identificare)\b")
RX_DATA_VERB = _R(r"\b" + REQ_VERB + r"\b")
RX_DATA_BANKLOGIN = _R(r"\b(?:intrati|intra|intrat|loga\w*|logheaza\w*|conecta\w*|accesa\w*|autentifica\w*|deschideti)\b[^.!?\n]{0,20}"
                       r"\b(?:in|pe)\s+(?:contul|aplicatia|internet banking|home ?bank\w*)\b[^.!?\n]{0,15}"
                       r"(?:de banca|bancar\w*|de internet banking|bancii|internet banking|home ?bank\w*|\bbancii\b)?")

MONEY = (r"(?:taxa\w*|taxe\w*|\d[\d.,]*\s*(?:de\s+)?(?:lei|ron|euro|eur|€|\$|usd|dolari)|€\s*\d|\bbani\b|\bbanii\b|\bsuma\w*|"
         r"\bplata\b|avans\w*|garanti\w*|depozit\w*|comision\w*|factur\w*|cautiun\w*|amend\w*|transfer\w*|cash|numerar|bitcoin|"
         r"crypto|criptomonede|usdt|card(?:uri)? cadou|paysafe|vouchere?)")
PAY_VERB = (r"(?:achitati|achita|achiti|platiti|plateste|platesti|plati|transferati|transfera|transferi|virati|vireaza|virezi|"
            r"depuneti|depune|depui|alimentati|alimenteaza|incarcati|incarca|trimiteti|trimite|trimiti|trimite-mi|trimiteti-mi|"
            r"da-mi|dati-mi|da mi(?![- ]?a\b)|dami|dati mi|da-ne|dati-ne|imprumuta\w*|investiti|investeste|investesti)")
# a sum of money with its currency: "1000 eur", "1.850 lei", "500 de euro", "1000€", "$200"
AMOUNT = (r"(?:\d[\d.,]*\s*(?:de\s+)?(?:(?:lei|ron|euro?|usd|dolari)\b|€|\$)|[€$]\s*\d|\b\d+(?:[.,]\d+)?\s*k\b|"
          # sums written as words: "doua sute cincizeci de lei", "o mie de lei", "zece mii"
          r"\b(?:(?:o|un|doua|doi|trei|patru|cinci|sase|sapte|opt|noua|zece|\w+sprezece|\w+zeci|suta|sute|mie|mii|si)\s+){0,4}"
          r"(?:suta|sute|mie|mii|zeci|\w+zeci|zece|\w+sprezece)\s+(?:de\s+)?(?:lei|ron|euro?|usd|dolari)\b|\b(?:o mie|(?:doua|trei|patru|cinci|sase|sapte|opt|noua|zece|\w+zeci) mii)\b)")
PAY_APP = (r"(?:revolut|paypal|western union|moneygram|card(?:uri)? cadou|gift ?card\w*|google play|steam|itunes|apple gift|"
           r"paysafe\w*|bitcoin|usdt|crypto|cripto\w*)")
# what the money is for, as asked: "ma ajuti cu ceva", "un mic ajutor", "ce poti", "orice suma"
HELP_ASK = (r"(?:ma ajuti|ma ajutati|ma poti ajuta|ma puteti ajuta|ajuta-?ma|ajutati-?ma|o mana de ajutor|un mic ajutor|un ajutor|"
            r"ajutor financiar|ma (?:scoti|scoateti|poti scoate|puteti scoate|salvezi|salvati) (?:tu |dumneavoastra )?din "
            r"(?:incurcatura|belea|impas|necaz|bucluc))")
RX_PAST = _R(r"\b(?:am|ai|a|au|ti-am|v-am|i-am|le-am|mi-ai|mi-ati)\s+(?:si\s+)?(?:platit|achitat|trimis|transferat|virat|depus|dat|"
             r"facut|luat|cumparat|primit|returnat|pus)\b")
# what the money is said to be for, when the request does not name a sum
PURPOSE = (r"\b(?:uber\w*|bolt\w*|taxi\w*|benzina|motorina|bilet\w*|drum\w*|transport\w*|tren\w*|avion\w*|autobuz\w*|autocar\w*|"
           r"chiri[ae]\w*|mancare|factur\w*|medicament\w*|spital\w*|operati\w*|cartela|reincarcare|abonament\w*|rata|ratele|"
           r"datori\w*|cazare|hotel\w*|viza|vama)\b")
# affection used as a lever; counts only next to a request (see detect)
# asking a stranger to pay a fee they described just before: "ma ajuti sa o achiti?", "poti tu sa platesti taxa?"
# (not used for saved contacts: "poti sa platesti tu la piata?" between spouses is not a scam signal)
RX_PAY_STRANGER = _R(r"\b(?:poti|puteti|ai putea|ati putea|ma ajuti|ma ajutati|ma poti ajuta|ma puteti ajuta)\b[^.!?\n]{0,20}"
                     r"\bsa (?:o |le |il |mi-?o |mi-?l |mi-?le )?(?:achiti|achitati|platesti|platiti|acoperi|acoperiti|depui|depuneti|suporti|"
                     r"suportati|trimiti|trimiteti)\b")
RX_LOVE = _R(r"\b(?:(?:mi-?e|imi e|imi este)\s+(?:foarte |tare |asa de |atat de )?dor\b|dor de tine|te iubesc|te ador|iubire\w*|"
             r"dragostea mea|sufletul meu|inima mea|(?:de )?abia astept sa (?:ne vedem|te vad|ne intalnim|fim impreuna)|"
             r"iubitule|iubito|iubita mea|iubitul meu|i miss (?:you|u)|miss you|love you|my love)")
RX_PAY = [
    _R(r"\b" + PAY_VERB + r"\b[^.!?\n]{0,50}" + MONEY),
    _R(r"\b(?:poti|puteti|ai putea|ati putea|te rog|va rog|ma ajuti|ma poti ajuta|ma puteti ajuta)\b[^.!?\n]{0,40}"
       r"\b(?:transfer\w*|vira\w*|trimit\w*|da|dai|dati|imprumut\w*|plat\w*|achit\w*|depun\w*)\b[^.!?\n]{0,40}"
       r"(?:\bbani\b|\bbanii\b|lei|euro|€|\bsuma\b|\d)"),
    _R(r"\b(?:fa|faceti|faci|sa-mi faci|sa imi faci)\s*(?:-?\s*mi\s+)?(?:tu\s+)?(?:un |o )?(?:transfer|virament|plata)\b"),
    _R(r"\b(?:am nevoie|avem nevoie|imi trebuie|imi trebuiesc|ne trebuie|mi-ar trebui|e nevoie)\b[^.!?\n]{0,30}(?:\bbani\b|" + AMOUNT + r"|o suma)"),
    # "imi dai si mie 1000 eur?", "ne trimiti 500 de lei"
    _R(r"\b(?:imi|mi|ne)\s+(?:dai|dati|trimiti|trimiteti|imprumuti|imprumutati|transferi|transferati|virezi|virati)\b[^.!?\n]{0,25}(?:\bbani\b|" + AMOUNT + r")"),
    # "vreau 1000 eur de la tine"
    _R(r"\bvreau\b[^.!?\n]{0,15}" + AMOUNT + r"[^.!?\n]{0,15}\bde la (?:tine|voi|dvs|dumneavoastra)\b"),
    # indirect requests that name what the money is for, not the money: "imi dai pentru un uber?",
    # "imi platesti tu biletul de avion?", "nu am bani de benzina, ma ajuti?", "ma poti ajuta cu chiria?"
    _R(r"\b(?:imi|mi|ne)\s+(?:dai|dati|trimiti|trimiteti|imprumuti|imprumutati)\b[^.!?\n]{0,20}\b(?:pentru|de)\s+(?:un |o |niste )?" + PURPOSE),
    _R(r"\b(?:imi|mi|ne)\s+(?:platesti|platiti|iei|luati|cumperi|cumparati|achiti|achitati)\b[^.!?\n]{0,20}?(?:un |o |niste )?" + PURPOSE),
    _R(r"\bnu (?:mai )?am (?:bani|niciun ban|cu ce)\b[^.!?\n]{0,60}\b(?:ma ajuti|ma ajutati|ma poti ajuta|ma puteti ajuta|ajuta-ma|ajutati-ma|"
       r"imi dai|imi dati|imi trimiti|imi imprumuti|sa imi dai|sa-mi dai)\b"),
    _R(r"\b(?:ma ajuti|ma ajutati|ma poti ajuta|ma puteti ajuta|ajuta-ma|ajutati-ma)\b[^.!?\n]{0,15}\bcu\s+(?:bani|ceva bani|niste bani|"
       r"chiria|rata|ratele|factura|facturile|datoria|o suma|un imprumut)\b"),
    # the same requests written in English
    _R(r"\b(?:send|give|lend|transfer|wire)\s+me\b[^.!?\n]{0,25}(?:\bmoney\b|" + AMOUNT + r")"),
    _R(r"\bi need\b[^.!?\n]{0,20}(?:\bmoney\b|" + AMOUNT + r")"),
    _R(r"\b(?:pregatiti|predati|lasati|dati)\b[^.!?\n]{0,20}\b(?:banii|suma|plicul)\b"),
    _R(r"\b(?:trebuie|e necesar|este necesar|e nevoie)\b[^.!?\n]{0,30}\b(?:sa )?(?:achitati|platiti|depuneti|virati|transferati|achiti|platesti|depui|achita|plateasca)\b"),
    _R(r"\b(?:plata|achitarea) (?:taxei|sumei|comisionului|garantiei|avansului)\b"),
    # ---- indirect asks (intent, not keywords)
    # "ma ajuti si tu cu ceva pentru un Uber?", "imi trebuie un mic ajutor pentru bilet"
    _R(r"\b" + HELP_ASK + r"\b[^.!?\n]{0,25}\b(?:cu (?:ceva |niste |cativa )?(?:bani|lei|o suma|un ban)\b|"
       r"cu (?:ce|cat) (?:poti|puteti)\b|cu orice suma\b|(?:pentru|de|cu)\s+(?:un |o |niste )?" + PURPOSE + r")"),
    # "pune 300 de euro, restul il fac eu", "baga 500 de lei pe platforma"
    _R(r"\b(?:pune|puneti|baga|bagati)\b[^.!?\n]{0,15}" + AMOUNT),
    _R(r"\b(?:am nevoie|avem nevoie|imi trebuie|ne trebuie|mi-ar trebui)\b[^.!?\n]{0,25}\b(?:un (?:mic )?imprumut|"
       r"(?:un )?(?:mic )?ajutor (?:financiar|cu bani)|(?:un )?(?:mic )?ajutor (?:pentru|de|la)\s+(?:un |o |niste )?" + PURPOSE + r"|" + PAY_APP + r"|"
       r"de (?:bn|banu|lovele|parale)\b)"),
    # "trimiteti ce puteti", "da-mi cat poti", "orice suma"
    _R(r"\b(?:trimite\w*|trimiti|da|dai|dati|da-mi|dati-mi|vireaza\w*|virati|transfera\w*)\b[^.!?\n]{0,30}"
       r"\b(?:ce poti|cat poti|ce puteti|cat puteti|orice suma|oricat|cat ai si tu|cat aveti)\b"),
    # "trimiteti ceva pentru chirie", "imi poti trimite tu pe numarul asta de cont"
    _R(r"\b(?:trimite\w*|trimiti|da-mi|dati-mi|dai|dati|vireaza\w*|virezi|virati|transfera\w*|depune\w*)\b(?![^.!?\n]{0,25}\bde mancare)"
       r"[^.!?\n]{0,25}\b(?:pentru|de)\s+(?:un |o |niste )?" + PURPOSE),
    _R(r"\b(?:trimite\w*|trimiti|vireaza\w*|virezi|virati|transfera\w*|transferi|depune\w*|depui|pune\w*)\b[^.!?\n]{0,30}"
       r"\b(?:pe|in|la) (?:contul|numarul (?:asta |acesta )?de cont|iban\w*|cont(?:ul)? (?:asta|acesta|lui|ei|indicat|de mai jos))"),
    # payment apps and gift cards: "pe Revolut", "un card cadou Google Play", "cumpara-mi un voucher paysafe"
    _R(r"\b(?:trimite\w*|trimiti|da-mi|dati-mi|vireaza\w*|virezi|transfera\w*|depune\w*|alimenteaz\w*|alimentezi|incarca\w*|incarci)\b"
       r"[^.!?\n]{0,40}\b(?:pe|prin|in) " + PAY_APP),
    _R(r"\b(?:cumpara|cumpara-mi|cumperi|cumparati|cumparati-mi|lua|luati|iei|ia-mi|ia|lua-mi)\b[^.!?\n]{0,25}\b" + PAY_APP),
    _R(r"(?<![\w-])" + PAY_APP + r"\b[^.!?\n]{0,15}" + AMOUNT + r"|" + AMOUNT + r"[^.!?\n]{0,15}\b(?:pe|prin|in) " + PAY_APP),
    # "imi faci si mie o alimentare pe Revolut?", "imi poti face o reincarcare de 50", "sa-mi alimentezi cartela"
    _R(r"\b(?:imi|mi|ne)\s+(?:poti |puteti )?(?:faci|faceti|face|fa)\b[^.!?\n]{0,20}\b(?:o |un )?(?:alimentare|transfer|plata|virament|"
       r"reincarcare|depunere)\b"),
    _R(r"\b(?:sa-?mi|sa imi|imi|mi)\s*-?\s*(?:alimentezi|alimentati|incarci|incarcati|reincarci|reincarcati)\b"),
    # "ai putea acoperi tu taxa de viza?", "daca ai putea contribui si tu cu ceva"
    _R(r"\b(?:poti|puteti|ai putea|ati putea|daca ai putea|daca ati putea|te rog|va rog)\b[^.!?\n]{0,25}"
       r"\b(?:acoperi|acoperiti|suporta|suportati|contribui|contribuiti)\b[^.!?\n]{0,25}"
       r"(?:\btaxa\w*|\bcost\w*|\bcheltuiel\w*|\bcu ceva|\bcu o suma|\bcu bani|" + PURPOSE + r")"),
    # cash out for someone: "treci pe la bancomat si scoti ceva, vine un prieten sa ia plicul"
    _R(r"\bbancomat\w*\b[^.!?\n]{0,40}\b(?:scoti|scoateti|scoate|retragi|retrageti|depui|depuneti)\b"
       r"|\b(?:scoti|scoateti|retragi|retrageti)\b[^.!?\n]{0,30}\bbancomat\w*"),
    # "va cer 100 de lei pentru medicamente", "trb dat bani la un domn"
    _R(r"\b(?:sa va cer|va cer|iti cer|sa iti cer|v-as cere|ti-as cere)\b[^.!?\n]{0,15}(?:" + AMOUNT + r"|\bbani\b|o suma)"),
    _R(r"\btrebuie\s+(?:dat|dati|sa dai|sa dati|sa trimiti|sa trimiteti|trimisi|platit)\b[^.!?\n]{0,20}(?:\bbani\b|" + AMOUNT + r")"),
]

RX_NEWNUM = [
    _R(r"\bnumar(?:ul)? (?:meu )?nou\b|\bnoul (?:meu )?numar\b|\b(?:un|pe un|de pe un|de pe alt|alt) numar(?: nou)?\b(?=[^.!?\n]{0,30}\b(?:meu|nou|salv|telefon))|"
       r"\bmi-?am schimbat (?:numarul|telefonul)\b|\bmi s-?a stricat telefonul\b|\bam (?:pierdut|spart|scapat|stricat) telefonul\b|"
       r"\btelefonul (?:meu )?(?:s-?a stricat|e stricat|e spart|s-?a spart|a cazut)\b|\bsalveaza\w*(?:-l|-ma)?\s+(?:numarul|noul)\b|"
       r"\bsalveaza-?(?:l|ma)\b|\bsterge numarul vechi\b|\bmi-?am (?:luat|cumparat) (?:un )?telefon nou\b|"
       # writing from someone else's phone: "de pe telefonul unui prieten", "de pe nr unui coleg"
       r"\b(?:de pe|de la|pe)\s+(?:telefonul|numarul|nr\.?|mobilul|whatsapp-ul)\s+(?:unui|unei|lui|altcuiva|cuiva|prietenului|prietenei|"
       r"colegului|colegei|unei doamne|unui domn)\b"),
    _R(r"\bsunt (?:eu,? )?(?:nepot\w*|fiul|fiica|copilul|baiatul|fata|fiu\w*) (?:tau|ta|dumneavoastra|dvs)\b|"
       r"^\W*(?:buna|salut|alo|hei|hey|sarut-?mana)?\W*(?:mami|mama|mamico|mamica|tati|tata|taticule|bunico|buni|bunicuta|bunicule|"
       r"mamaie|tataie|matusa|unchiule)\b[^.!?\n]{0,40}\b(?:sunt eu|eu sunt)\b"),
]

RX_SECRECY = [
    _R(r"\bnu\s*-?\s*(?:i|le|ii)\s*-?\s*(?:spune|spuneti|zice|ziceti|povesti\w*|da de stire|anunta\w*)\b"),
    _R(r"\b(?:nu|n-o|n-ii|n-i)\s*-?\s*(?:o |le |ii )?(?:spune|spuneti|zice|ziceti|zi|povesti|povestiti|vorbi|vorbiti|discuta|discutati|anunta|"
       r"anuntati|comenta)\b[^.!?\n]{0,25}"
       r"\b(?:nimanui|nimic|cu nimeni|la nimeni|nimeni|familiei|copiilor|lui|bancii|politiei|sotului|sotiei|fiului|fiicei|vecinilor|altcuiva|la banca|la politie)\b"),
    _R(r"\b(?:sa ramana|ramane|e|este|ramana)(?: doar)? (?:intre noi|secret\w*|confidential\w*)\b|\bsecretul nostru\b|"
       r"\bsa nu (?:afle|stie) (?:nimeni|tata|mama|familia|copiii|altcineva|banca)\b|\bfara sa (?:stie|afle) (?:nimeni|tata|mama|familia|copiii|banca)\b|"
       r"\bnu (?:sunati|mergeti|va duceti|contactati|intrebati|suna|merge)\b[^.!?\n]{0,25}\b(?:banca|la banca|politi\w*|familia|copiii|pe nimeni|altcineva)\b"),
]
RX_SECRECY_CODE = _R(r"\bcod\w*|\bparol\w*|\bpin\b|\botp\b")

RX_TOOGOOD = [
    _R(r"\b(?:ati castigat|ai castigat|castigatorul|castigatoarea|ati fost (?:ales|alesa|selectat\w*)|ai fost (?:ales|alesa|selectat\w*)|"
       r"marele premiu|premiul cel mare|premiu\w*|tombola|extragere\w*|loteri\w*|jackpot|cadou gratuit|"
       r"profit\w* garantat\w*|castig\w* garantat\w*|garantat\w* (?:profit|castig)\w*|randament\w* (?:garantat\w*|de \d)|fara (?:niciun |nici un )?risc|"
       r"bani (?:usori|rapizi|multi fara)|venit\w* (?:pasiv|suplimentar|garantat)\w*|\d+\s*(?:%|la suta) (?:pe|in|pentru) (?:zi|luna|saptamana)|"
       r"(?:dubla\w*|tripla\w*|inmulti\w*) (?:banii|investitia|suma|castigul)|mostenire)\b"),
    _R(r"\b(?:castigati|castigi|castiga)\b[^.!?\n]{0,30}(?:\d|bani|lei|euro|€|premi)"),
    _R(r"\b(?:vesti bune|vestea buna|vestea cea buna)\b[^.!?\n]{0,80}(?:lei|bani|pensia|suma|creste|bonus|prim\w*|castig\w*)"),
    _R(r"\b(?:va creste cu|veti primi (?:in plus|un bonus|o suma|suplimentar)|bonus\w* de \d)"),
    _R(r"\bvoucher\w* (?:gratuit\w*|cadou|de \d+)"),
]
RX_FELICITARI = _R(r"\bfelicitari\b")
RX_PRIZE_CTX = _R(r"castig|premi|ales|selectat|tombola|bonus|voucher|cadou")

RX_IMPERS = [
    _R(r"^\W{0,3}" + ORG + r"(?:\s+[a-z]+){0,2}\s*[:\-]"),
    _R(r"\b(?:sunt|suntem|va sun|va sunam|te sun|te sunam|va contactam|va contactez|va scriem|va scriu|va informam|reprezint|"
       r"reprezentam|aici|eu sunt)\b[^.!?\n]{0,50}\b(?:de la|din partea|din cadrul)\s+" + ORG),
    _R(ORG + r"\s+(?:va informeaza|va anunta|va notifica|va ofera|va contacteaza|informeaza|anunta|va roaga|va solicita)"),
    _R(r"\b(?:tombola|concurs\w*|campani\w*|extrager\w*|loteri\w*)\b[^.!?\n]{0,25}" + ORG + r"|" + ORG + r"[^.!?\n]{0,25}\b(?:tombola|concurs\w*|extrager\w*|loteri\w*)\b"),
    _R(r"\b(?:sunt|ma numesc|numele meu este|va sun|va vorbeste)\b[^.!?\n]{0,30}\b(?:agent\w* de politie|inspector\w*|ofiter\w*|politist\w*|"
       r"procuror\w*|consilier\w* (?:bancar\w*|de la banca)|reprezentant\w* (?:al|al bancii|bancii)|angajat\w* (?:al|la) banc\w*|"
       r"tehnician\w*|executor\w*)\b"),
]
RX_ORG = _R(ORG)
RX_SENDER_NOT_ORG = _R(r"cumparator|vanzator|client\b|utilizator|prieten|vecin|mama|tata|fiul|fiica")

RX_URG_STRONG = _R(
    r"\b(?:urgent\w*|imediat|de urgenta|cat mai (?:repede|curand)|fara intarziere|in cel mai scurt timp|grabiti-?\s?va|grabeste-?te|"
    r"ultima (?:zi|sansa|ocazie)|expira\w*|nu mai (?:e|este|avem|aveti) timp|"
    r"in (?:urmatoarele|maxim|max|doar|cel mult) \d+\s*(?:h|ore|de ore|minute|min|de minute)\b|"
    r"termen(?:ul)? limita|acum sau niciodata|chiar acum|in caz contrar|altfel (?:veti|pierdeti|contul|cardul|o sa))")
# a time window is pressure only next to a request or a threat: "platiti in 2 ore" yes, "ajung in 10 minute" / "azi la 5" no
RX_URG_TIMED = _R(
    r"\b(?:in \d+\s*(?:h|ore|de ore|minute|min|de minute)\b|in \d+h\b|\d+\s*h\b(?! ?-)|intr-o ora|intr-o jumatate de ora|"
    r"(?:aveti|ai|doar|numai|in termen de) \d+ (?:de )?zile\b|"
    r"pana (?:la|in|pe)\s+(?:data de\s+)?\d{1,2}(?:[./]\d{1,2}|\s+(?:ian|feb|mar|apr|mai|iun|iul|aug|sep|oct|noi|dec)\w*)|"
    r"pana (?:azi|astazi|maine|diseara|deseara|la ora|la sfarsitul zilei|la miezul noptii|vineri|luni|marti|miercuri|joi)\b)")
RX_URG_TIMED_CTX = _R(r"\b(?:trebuie|plati\w*|platesti|achit\w*|transfer\w*|trimite\w*|trimiti|vira\w*|cod\w*|depun\w*|imprumut\w*|"
                      r"confirma\w*|introdu\w*|complet\w*|actualiz\w*|acces\w*|intra\w*|raspunde\w*|sunati|suna|"
                      r"revendic\w*|activa\w*|activeaza\w*|valida\w*|profita\w*|inscrie\w*|"
                      r"blocat\w*|suspendat\w*|anulat\w*|anuleaza|inchis\w*|pierde\w*|returnat\w*|distrus\w*|amend\w*|altfel|sau se)\b")
RX_URG_WEAK = _R(r"\b(?:azi|astazi|acum|diseara|repede|in seara asta)\b")
RX_URG_CTX = _R(r"\b(?:trebuie|plati\w*|achit\w*|transfer\w*|trimite\w*|trimiti|vira\w*|cod\w*|depun\w*|"
                r"imprumut\w*)\b")

RX_THREAT = [
    _R(r"\b(?:card\w*|cont\w*|acces\w*|abonament\w*|linia|profil\w*|pensia|dosar\w*|numarul de telefon)\b[^!?\n]{0,40}"
       r"\b(?:blocat\w*|suspendat\w*|dezactivat\w*|inchis\w*|restrictionat\w*|anulat\w*|sters\w*|sistat\w*|sechestrat\w*|"
       r"compromis\w*|spart\w*|piratat\w*|clonat\w*|accesat\w* (?:neautorizat|de altcineva|fraudulos))"),
    _R(r"\b(?:va fi|vor fi|o sa fie|riscati sa fie|urmeaza sa fie)\s+(?:blocat|suspendat|dezactivat|inchis|anulat|sters|sistat)\w*"),
    _R(r"\b(?:amenda|amenzi|penalitat\w*|penalizar\w*|dosar penal|plangere penala|cercetare penala|cercetat\w* penal|inchisoare|puscarie|"
       r"mandat de arestare|executare silita|poprire|sechestru|urmarire penala|veti fi (?:amendat|cercetat|chemat|arestat|dat in judecata)|"
       r"in instanta|in judecata)\b"),
    _R(r"\b(?:virus\w*|malware|infectat\w*|virusat\w*|hackuit\w*|atacat\w* de hackeri|hackeri)\b"),
    _R(r"\b(?:veti pierde|pierdeti|o sa pierdeti|riscati sa pierdeti|riscati)\b\s+(?:contul|cardul|accesul|banii|economiile|pensia|dreptul)"),
    _R(r"\b(?:tranzacti\w*|plat\w*|retrager\w*|activitate\w*|transfer\w*|logar\w*|autentificar\w*) (?:suspect\w*|neautorizat\w*|frauduloas\w*|neobisnuit\w*)"),
]

RX_EMO = _R(
    r"\b(?:accident\w*|spital\w*|am fost (?:arestat|retinut|batut|jefuit|talharit)\w*|e (?:arestat|retinut)\w*|a fost (?:arestat|retinut)\w*|"
    r"sunt la politie|e la politie|arest\w*|ma (?:a )?bagat (?:politia|la)\w*|e internat\w*|operati\w* urgent\w*|e (?:foarte )?grav\b|sunt in pericol|e in pericol|disperat\w*|plang\b|plang\w*|ajuta-?ma|"
    r"ajutati-?ma|salveaza-?ma|te implor|va implor|nu am pe nimeni|numai tu ma|doar tu ma|daca ma iubesti|daca tii la mine|o sa mor|"
    r"bolnav\w* grav|nu mai am (?:bani|ce manca)|mi-?e frica|mi-?e teama|sufar|ma vor omori|ma omoara|in panica|am necaz\w*|necaz mare)\b")

APPS = r"(?:telegram|whats ?app|signal|viber|messenger|instagram|facebook|skype|wechat|e-?mail\w*|mail\w*)"
RX_SWITCH = [
    _R(r"\b(?:vorbim|vorbi|discutam|continuam|comunicam|ramanem in legatura|scrie-?mi|scrieti-?mi|scrie|scrieti|contacteaza-?ma|"
       r"contactati-?ma|contactati-?ne|adauga-?ma|adaugati-?ma|mutam|trecem|da-?mi|dati-?mi|ma gasesti|ma gasiti|sunati-?ma|suna-?ma)\b"
       r"[^.!?\n]{0,30}\b(?:pe|in|prin)\s+(" + APPS + r")\b"),
    _R(r"\b(?:t\.me|wa\.me|chat\.whatsapp\.com)/"),
    _R(r"\b(?:descarca\w*|instala\w*)\s+(?:aplicatia\s+)?(telegram|signal|viber)\b"),
]


# ----------------------------------------------------------------------------------------------- detect

def _add(out, code, m, g=0):
    try:
        out.append({"code": code, "start": int(m.start(g)), "end": int(m.end(g))})
    except Exception:
        pass


def detect(text, ctx=None):
    out = []
    spanmap = []
    try:
        if not isinstance(text, str):
            text = "" if text is None else str(text)
        ctx = ctx if isinstance(ctx, dict) else {}
        t = text[:MAX_LEN]
        ft, spanmap = normalise(fold(t))
        if not ft.strip():
            return out
        sents = _sentences(ft)
        channel = str(ctx.get("channel") or "").lower()
        known = bool(ctx.get("known_contact"))
        sender = ctx.get("sender") if isinstance(ctx.get("sender"), dict) else {}

        def ok(m, protective_check=True):
            a, _b = _sent_of(sents, m.start())
            if _neg(ft, m.start(), a):
                return False
            if protective_check and _protective(ft, sents, m.start()):
                return False
            return True

        # RF_CODE_REQUEST
        def code_ok(m):
            a, b = _sent_of(sents, m.start())
            return ok(m) and not RX_CODE_HARMLESS.search(ft[a:b])

        for rx in RX_CODE:
            for m in _finditer(rx, ft):
                if code_ok(m):
                    _add(out, "RF_CODE_REQUEST", m)
        if RX_CODE_CTX.search(ft):
            for m in _finditer(RX_CODE_PRON, ft):
                if code_ok(m):
                    _add(out, "RF_CODE_REQUEST", m)
            for rx in (RX_CODE_PRON2, RX_CODE_ASK):
                for m in _finditer(rx, ft):
                    if code_ok(m):
                        _add(out, "RF_CODE_REQUEST", m)
        if len(ft.strip()) <= 30:
            for m in _finditer(RX_CODE_SHORT, ft):
                _add(out, "RF_CODE_REQUEST", m)

        # RF_REMOTE_ACCESS
        for rx in RX_REMOTE:
            for m in _finditer(rx, ft):
                if ok(m):
                    _add(out, "RF_REMOTE_ACCESS", m)

        # RF_DATA_REQUEST: sensitive data noun + request verb in the same sentence, or a list of >=2 sensitive items
        nouns = [m for m in _finditer(DATA_NOUN, ft) if ok(m)]
        distinct = {re.sub(r"\W", "", m.group(0))[:6] for m in nouns}
        for m in nouns:
            a, b = _sent_of(sents, m.start())
            verb_ok = False
            for v in _finditer(RX_DATA_VERB, ft[a:b]):
                if not _neg(ft, a + v.start(), a):
                    verb_ok = True
                    break
            if verb_ok or len(distinct) >= 2:
                _add(out, "RF_DATA_REQUEST", m)
        for m in _finditer(RX_DATA_BANKLOGIN, ft):
            seg = ft[m.start():m.end() + 25]
            if re.search(r"banc|banking|home ?bank", seg) and ok(m):
                _add(out, "RF_DATA_REQUEST", m)

        # RF_PAYMENT_REQUEST
        for rx in RX_PAY:
            for m in _finditer(rx, ft):
                if ok(m, protective_check=False):
                    seg = ft[m.start():m.end()]
                    # "ca sa primiti banii" / "va trimitem banii" are not requests to pay
                    if re.search(r"\b(?:primiti|primesti|primi|va trimitem|iti trimit|va trimit|v-am trimis|ti-am trimis|va virez|iti virez|"
                                 r"va platesc|iti platesc|va transfer|iti transfer)\b", seg):
                        continue
                    # money already paid or given back is not a request ("ti-am dat banii inapoi pe Revolut")
                    a_, _b = _sent_of(sents, m.start())
                    if RX_PAST.search(ft[max(a_, m.start() - 12):m.end()]):
                        continue
                    _add(out, "RF_PAYMENT_REQUEST", m)
        if not known:
            for m in _finditer(RX_PAY_STRANGER, ft):
                if ok(m, protective_check=False):
                    _add(out, "RF_PAYMENT_REQUEST", m)

        # RF_NEW_NUMBER: only from a sender not saved in the contacts
        if not known and channel != "email":
            for rx in RX_NEWNUM:
                for m in _finditer(rx, ft):
                    _add(out, "RF_NEW_NUMBER", m)

        # RF_SECRECY (but "do not share this code" is protection, not secrecy)
        for rx in RX_SECRECY:
            for m in _finditer(rx, ft):
                a, b = _sent_of(sents, m.start())
                if RX_SECRECY_CODE.search(ft[a:b]):
                    continue
                _add(out, "RF_SECRECY", m)

        # RF_TOO_GOOD
        for rx in RX_TOOGOOD:
            for m in _finditer(rx, ft):
                if ok(m, protective_check=False):
                    _add(out, "RF_TOO_GOOD", m)
        for m in _finditer(RX_FELICITARI, ft):
            if RX_PRIZE_CTX.search(ft):
                _add(out, "RF_TOO_GOOD", m)

        # RF_IMPERSONATION (fusion drops it for genuine organisation messages)
        for rx in RX_IMPERS:
            for m in _finditer(rx, ft):
                _add(out, "RF_IMPERSONATION", m)
        sname = fold(str(sender.get("name") or ""))
        if sname and RX_ORG.search(sname) and not RX_SENDER_NOT_ORG.search(sname) and int(ctx.get("n") or 1) >= 1:
            mo = RX_ORG.search(ft)
            out.append({"code": "RF_IMPERSONATION", "start": mo.start() if mo else 0, "end": mo.end() if mo else 0})

        # RF_URGENCY
        for m in _finditer(RX_URG_STRONG, ft):
            if ok(m, protective_check=False):
                _add(out, "RF_URGENCY", m)
        for m in _finditer(RX_URG_TIMED, ft):
            a, b = _sent_of(sents, m.start())
            if RX_URG_TIMED_CTX.search(ft[a:b]) and not RX_PAST.search(ft[a:b]) and ok(m, protective_check=False):
                _add(out, "RF_URGENCY", m)
        for m in _finditer(RX_URG_WEAK, ft):
            a, b = _sent_of(sents, m.start())
            # "am platit eu factura azi" is news, not pressure
            if RX_URG_CTX.search(ft[a:b]) and not RX_PAST.search(ft[a:b]) and ok(m, protective_check=False):
                _add(out, "RF_URGENCY", m)

        # RF_THREAT
        for rx in RX_THREAT:
            for m in _finditer(rx, ft):
                if ok(m, protective_check=False):
                    _add(out, "RF_THREAT", m)

        # RF_EMOTIONAL_PRESSURE
        for m in _finditer(RX_EMO, ft):
            if ok(m, protective_check=False):
                _add(out, "RF_EMOTIONAL_PRESSURE", m)
        # affection ("mi-e dor de tine", "te iubesc") is pressure only when money, data or a code is being
        # asked for, in this message or earlier in the thread; on its own it is just a warm message
        _asks = {"RF_PAYMENT_REQUEST", "RF_DATA_REQUEST", "RF_CODE_REQUEST"}
        if (_asks & {f.get("code") for f in out}) or (_asks & set(ctx.get("prior_flags") or [])):
            for m in _finditer(RX_LOVE, ft):
                _add(out, "RF_EMOTIONAL_PRESSURE", m)

        # RF_CHANNEL_SWITCH
        cur = {"whatsapp": "whats", "email": "mail", "sms": "sms", "chat": "chat", "call_transcript": "call"}.get(channel, channel)
        for rx in RX_SWITCH:
            for m in _finditer(rx, ft):
                target = (m.group(1) if m.groups() and m.group(1) else m.group(0)).replace(" ", "")
                if cur and cur in target:
                    continue
                if ok(m, protective_check=False):
                    _add(out, "RF_CHANNEL_SWITCH", m)
    except Exception:
        pass
    # map spans from the normalised text back to the original text, then clip
    n = len(text) if isinstance(text, str) else 0
    res = []
    for h in out:
        s, e = h["start"], h["end"]
        try:
            if spanmap and e > s:
                s, e = spanmap[min(s, len(spanmap) - 1)][0], spanmap[min(e, len(spanmap)) - 1][1]
            elif spanmap:
                s = e = spanmap[min(s, len(spanmap) - 1)][0]
        except Exception:
            pass
        s, e = max(0, min(s, n)), max(0, min(e, n))
        res.append({"code": h["code"], "start": s, "end": e})
    return res


# ----------------------------------------------------------------------------------------------- extras for fusion / warnings

_NOT_NAMES = {"Bună", "Buna", "Mami", "Mama", "Tati", "Tata", "Bunico", "Buni", "Salut", "Eu", "Sunt", "Aici", "Da", "Nu", "Te",
              "Vă", "Va", "Ce", "Cine", "Bine", "Mersi", "Doamnă", "Doamna", "Domnule", "Ok", "Hei", "Alo", "Mamă", "Tată"}
_NAME_RX = re.compile(
    r"(?:\b(?:[Ee]u(?:\s+sunt)?|[Ss]unt(?:\s+eu)?|[Aa]ici\s+(?:e|este)|[Mm]ă\s+numesc|[Mm]a\s+numesc|[Nn]umele\s+meu\s+(?:e|este))\s*,?\s*)"
    r"([A-ZĂÂÎȘŞȚŢ][a-zăâîșşțţ]{2,})")


def person_name(text):
    """First name the sender gives for themself ("Eu, Andrei", "sunt Andrei"), or None."""
    try:
        for m in _NAME_RX.finditer(text or ""):
            nm = m.group(1)
            if nm not in _NOT_NAMES:
                return nm
    except Exception:
        pass
    return None


def org_mentions(text):
    """generic organisation words (folded) named in the text."""
    try:
        return [m.group(0) for m in RX_ORG.finditer(fold(text or "")[:MAX_LEN])]
    except Exception:
        return []
