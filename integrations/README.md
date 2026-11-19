# Integrări – 2nd Eye (AlgoR3IthM)

Un singur detector local, mai multe „uși de intrare”. Ambele integrări trimit textul doar către API-ul de pe acest laptop
(`http://localhost:8000`). Fără serviciu AI în cloud, fără stocarea sau logarea textului mesajelor.

Porniți mai întâi serverul (vezi README-ul din rădăcină) și verificați `http://localhost:8000/api/health`.

## 1. Botul Telegram

**Token (o singură dată):**
1. În Telegram deschideți `@BotFather`, trimiteți `/newbot`, alegeți un nume și un utilizator care se termină în `bot`.
2. Copiați tokenul primit.
3. Copiați `integrations/.env.example` ca `.env` în **rădăcina proiectului** și scrieți `TELEGRAM_BOT_TOKEN=<token>`. Tokenul nu se pune niciodată în cod.

**Rulare:**
```
.venv\Scripts\python.exe integrations\telegram_bot.py
```
Deschideți botul în Telegram, apăsați Start, apoi trimiteți sau redirecționați un mesaj suspect.
Mai multe redirecționări la mai puțin de 3 secunde una de alta sunt tratate ca o singură conversație.
La mesajele redirecționate al căror expeditor original este vizibil apare butonul „Îl cunosc”; după apăsare,
mesajele viitoare de la el trec doar prin „tripwire” (bani, coduri, acces la telefon). Lista este doar în memorie și dispare la oprirea botului.

## 2. Extensia Chrome pentru WhatsApp Web

1. Chrome → `chrome://extensions` → activați „Developer mode”.
2. „Load unpacked” → alegeți folderul `integrations/extension`.
3. Deschideți `https://web.whatsapp.com` și o conversație. Număr de telefon în antet = necunoscut → analiză completă.
   Nume salvat → doar tripwire (`?trust_gate=true`).
4. Bannerul roșu/portocaliu apare sus în conversație, cu mesajul primei alerte încadrat. Pentru „în regulă” apare doar o bifă verde mică.

## 3. Demo fără cont WhatsApp

Deschideți `integrations/extension/demo.html` (dublu-click sau `http://localhost:<port>/demo.html` dintr-un server static).
Pagina are o conversație falsă și trei butoane (țeapă „număr nou”, contact salvat banal, contact salvat care cere un cod) și folosește
același `content.js`. Cu serverul local pornit, bannerul apare în ~1 secundă.
Dacă deschiderea ca fișier (`file://`) este blocată de CORS, serviți folderul: `python -m http.server 8080 --directory integrations\extension`
și, dacă e nevoie, cereți colegului de server să permită originea respectivă în CORS.

## Limite (sincer)

- WhatsApp Web își schimbă des structura paginii; selectorii din blocul `SEL` din `content.js` pot necesita ajustări. Dacă nu se potrivește nimic, extensia tace.
- Extensia citește doar mesajele încărcate pe ecran (ultimele 30) și detectează „necunoscut” după faptul că antetul este un număr.
- Pe Telegram, expeditorul original al unui mesaj redirecționat nu este mereu vizibil (setări de confidențialitate); atunci nu apare „Îl cunosc”.
- Nu am putut testa cu un token Telegram real sau un cont WhatsApp real; testat doar sintactic și prin pagina demo.
- Doar română, fără mesaje vocale sau imagini, doar text.
- Dacă API-ul local nu rulează, botul răspunde calm că nu poate verifica, iar extensia nu afișează nimic.
