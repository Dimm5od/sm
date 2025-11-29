// noinspection JSDeprecatedSymbols

function bytesToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return bytesToHex(buf);
}

function sha256ToIcons(hash, iconCount = 4) {
    const CATEGORIES = [ // Животные (36)
        ["🐱", "🐶", "🐭", "🐰", "🦊", "🐼", "🐨", "🐯", "🦁", "🐷", "🐸", "🐵", "🦉", "🦅", "🦆", "🦋", "🐠", "🦈",
            "🐺", "🦬", "🐮", "🐑", "🐐", "🐎", "🦄", "🐍", "🦎", "🦖", "🦕", "🐙", "🦀", "🦞", "🦩", "🐧", "🦢", "🦜", "🦝"],

        // Природа (36)
        ["🌵", "🌲", "🌴", "🌸", "🌻", "🌼", "🍁", "🍄", "⛰️", "🏔️", "🏝️", "🏜️", "🌞", "🌙", "⭐", "⚡", "🔥", "💎",
            "🌱", "🌿", "☘️", "🍂", "🌪️", "🌈", "❄️", "💧", "🌊", "⛅", "🌖", "🌋", "🪨", "🌾", "🏞️", "🪵", "🪴", "🫧"],

        // Еда (36)
        ["🍎", "🍐", "🍊", "🍋", "🍉", "🍇", "🍓", "🍒", "🥝", "🥑", "🌽", "🍔", "🍟", "🍕", "🥐", "🍩", "🍪", "🍯",
            "🍌", "🍑", "🥭", "🍍", "🍗", "🍖", "🥓", "🌭", "🍣", "🍤", "🍜", "🍝", "🥗", "🥨", "🌮", "🌯", "🍰", "🍫"],

        // Предметы (36)
        ["💡", "🔧", "🛠", "🔨", "🔑", "🔒", "🧲", "📦", "📌", "📎", "📍", "🖊️", "📘", "📕", "📚", "🧭", "🧱", "🪚",
            "🔍", "🖋️", "🖱️", "⌨️", "💾", "🖨️", "🧮", "📏", "📐", "📂", "📁", "🧰", "🗜️", "🪛", "🧪", "🧫", "🧬", "📡"],

        // Транспорт (36)
        ["🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚜", "🚛", "🚚", "🚐", "✈️", "🚁", "🚤", "⛵", "🚀",
            "🛶", "🚂", "🚆", "🚄", "🚇", "🚈", "🚉", "🛻", "🚍", "🛵", "🏍️", "🛴", "🚲", "🚡", "🚠", "🚝", "🛸", "🛥️"],

        // Развлечения и символы (36)
        ["🎯", "🎲", "🎮", "🧩", "🏆", "🎵", "🎧", "🎷", "🎺", "🎻", "🎸", "🎹", "📀", "🎥", "🎬", "🎪", "🎭", "🀄",
            "🎳", "🎱", "🥇", "🥈", "🥉", "🎽", "🎤", "🎼", "🪗", "🥁", "📸", "📹", "🎨", "🎟️", "🎡", "🎢", "🎠", "🎋"]];

    if (hash.length !== 64) return "🐱🐱🐱🐱";

    const result = [];
    const used = new Set();

    for (let i = 0; i < iconCount; i++) {
        // Берём по 4 символа для категории
        const catPart = hash.slice(i * 4, i * 4 + 4);
        const catNum = parseInt(catPart, 16);
        const categoryIndex = catNum % CATEGORIES.length;
        const category = CATEGORIES[categoryIndex];

        // Берём по 4 символа для иконки (со сдвигом)
        const iconPart = hash.slice((i * 4 + 16) % 64, (i * 4 + 20) % 64);
        const iconNum = parseInt(iconPart, 16);
        let idx = iconNum % category.length;

        // Уникальность строго по итоговой строке
        let attempts = 0;
        while (used.has(`${categoryIndex}-${idx}`) && attempts < category.length) {
            idx = (idx + 1) % category.length;
            attempts++;
        }

        used.add(`${categoryIndex}-${idx}`);
        result.push(category[idx]);
    }

    return result.join("");
}


//// детерминированное шифрование /////

// ---------- утилиты ----------
async function sha256hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// HMAC-SHA256 -> hex
async function hmacSha256Hex(keyBytes, msgStr) {
    const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msgStr));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// hex -> Uint8Array
function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, (i * 2) + 2), 16);
    return out;
}

// стабильный PRNG по 32-бит seed
function mulberry32(seed) {
    return function () {
        let t = seed += 0x6D2B79F5;
        t = Math.imul(t ^ t >>> 15, t | 1);
        t ^= t + Math.imul(t ^ t >>> 7, t | 61);
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    }
}

// ---------- генерация кодовой таблицы ----------
/*
Формируем массив кодов:
- 52 однобуквенных: a..z A..Z
- 52*52 двухбуквенных: все пары из a..z A..Z
Затем детерминированно перетасовываем, seed из (login + secret_key).
*/
function buildCodebook(secretKey) {
    const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const codes = [];

    // 1-символьные
    for (let i = 0; i < letters.length; i++) codes.push(letters[i]);

    // 2-символьные (всего 2704)
    for (let i = 0; i < letters.length; i++) {
        for (let j = 0; j < letters.length; j++) {
            codes.push(letters[i] + letters[j]);
        }
    }

    // тасуем детерминированно
    const seedStr = `${secretKey}:v1-codebook`;
    let seed = 0;
    for (let i = 0; i < seedStr.length; i++) seed = (seed + seedStr.charCodeAt(i)) >>> 0;
    const rand = mulberry32(seed);
    for (let i = codes.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [codes[i], codes[j]] = [codes[j], codes[i]];
    }
    return codes; // длина 52 + 2704 = 2756
}

// ---------- нормализация для FULLTEXT ----------
/*
Приводим к нижнему регистру — FULLTEXT по умолчанию case-insensitive.
*/
function normalizeForFT(s) {
    s = s.normalize('NFKC');            // приведение форм Unicode
    s = s.toLowerCase();               // приводим к нижнему регистру
    return s;
}


// ---------- одностороннее кодирование ----------
/*
Для каждого символа (буква/цифра) считаем idx = HMAC_SHA256(key2, char) % CODES_LEN,
и добавляем позиционный сдвиг (p * step) для p>0, где step = (HMAC_SHA256(key3, 'step') % CODES_LEN) | 1
— нечётный шаг гарантирует «пробег» по всему кольцу.
*/
async function makeEncState(secretKey) {
    const codes = buildCodebook(secretKey);
    const codesLen = codes.length;

    // derive двa ключа для HMAC (из sha256(secretKey))
    const rootHex = await sha256hex(`${secretKey}:v1`);
    // key2 и key3 просто разные «соль + корень»
    const key2 = hexToBytes(await sha256hex(rootHex + ':key2'));
    const key3 = hexToBytes(await sha256hex(rootHex + ':key3'));

    const stepHex = await hmacSha256Hex(key3, 'step');
    let step = (parseInt(stepHex.slice(0, 8), 16) % codesLen) | 1; // нечётный

    // внутри makeEncState(...)
    async function encodeWord(word) {
        if (!word) return '';
        let out = '';
        let pos = 0;

        for (const ch of word) {
            // Только "_" оставляем как есть и сбрасываем сдвиг.
            if (ch === '_') {
                out += '_';
                pos = 0;
                continue;
            }

            const h = await hmacSha256Hex(key2, ch);
            let idx = parseInt(h.slice(0, 8), 16) % codesLen;
            if (pos > 0) idx = (idx + pos * step) % codesLen;
            out += codes[idx];
            pos++;
        }

        return out;
    }


    async function encodeForIndex(raw) {
        const norm = normalizeForFT(raw);  // уже NFKC + lowercased
        const MIN_WORD_LENGTH = 3;
        let result = '';
        let currentWord = '';
        let atWordStart = true; // определяем, в начале ли мы слова

        for (const ch of norm) {
            if (/\s/.test(ch)) {
                // завершение слова
                if (currentWord.length >= MIN_WORD_LENGTH) {
                    result += await encodeWord(currentWord);
                }
                currentWord = '';
                atWordStart = true;
                if (!result.endsWith(' ')) result += ' ';
            } else if (/[+\-]/.test(ch)) {
                if (atWordStart) {
                    // сохраняем плюс или минус как есть
                    result += ch;
                    atWordStart = true; // после него остаемся перед словом
                } else {
                    // плюс или минус внутри слова — включаем в кодируемую часть
                    currentWord += ch;
                }
            } else if (/[\p{L}\p{Nd}_]/u.test(ch)) {
                // начало или продолжение слова
                currentWord += ch;
                atWordStart = false;
            }
            // остальное — игнорируем
        }

        // обрабатываем хвост
        if (currentWord.length >= MIN_WORD_LENGTH) {
            result += await encodeWord(currentWord);
        }

        return result.trim();
    }


    return {encodeForIndex, codesLen};
}

// Функция генерации ключа AES из passphrase
async function getAesKey(passphrase, aesSalt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        {name: "PBKDF2"},
        false,
        ["deriveKey"]
    );
    const salt = enc.encode(aesSalt); // можно хранить глобально или с пользователем
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
    );
}

// PBKDF2(SHA-256) -> 32 bytes (256 bits) -> hex(64)
async function deriveClientKeyHex(passphrase, loginSalt, iterations = 100000) {
    const enc = new TextEncoder();
    // 1) import raw passphrase as key material
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        {name: 'PBKDF2'},
        false,
        ['deriveBits', 'deriveKey']
    );
    // 2) derive 256 bits
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: enc.encode(loginSalt),   // salt = login (или login + какой-то fixed suffix)
            iterations: iterations
        },
        keyMaterial,
        256 // bits length
    );
    // 3) return hex (64 chars)
    return bytesToHex(derivedBits);
}


// --- Константы ---
const CHUNK_SIZE = 32 * 1024; // 32KB на чанк
const IV_SIZE = 12;           // IV для AES-GCM (96 бит)

// --- Вспомогательные функции ---
function uint8ToBase64(u8) {
    let binary = '';
    const CHUNK = 0x8000; // конвертация блоками
    for (let i = 0; i < u8.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    }
    return btoa(binary);
}

function base64ToUint8(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const u8 = new Uint8Array(len);
    for (let i = 0; i < len; i++) u8[i] = binary.charCodeAt(i);
    return u8;
}

// --- Шифрование ---
async function encryptText(plaintext, key) {
    const enc = new TextEncoder();
    const textBytes = enc.encode(plaintext);
    const chunks = [];

    // Разбиваем на чанки
    for (let offset = 0; offset < textBytes.length; offset += CHUNK_SIZE) {
        const part = textBytes.subarray(offset, offset + CHUNK_SIZE);
        const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            {name: "AES-GCM", iv},
            key,
            part
        ));

        // Формат: [4 байта длины блока][12 байт IV][шифротекст]
        const chunkLen = ciphertext.length;
        const block = new Uint8Array(4 + IV_SIZE + chunkLen);
        const dv = new DataView(block.buffer);
        dv.setUint32(0, chunkLen, false); // big-endian
        block.set(iv, 4);
        block.set(ciphertext, 4 + IV_SIZE);
        chunks.push(block);
    }

    // Собираем всё в один бинарный массив
    const totalLen = chunks.reduce((sum, b) => sum + b.length, 0);
    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const b of chunks) {
        result.set(b, pos);
        pos += b.length;
    }

    // Возвращаем Base64
    return uint8ToBase64(result);
}

// --- Расшифровка ---
async function decryptText(dataB64, key) {
    let data;
    try {
        data = base64ToUint8(dataB64);
    } catch (err) {
        console.error("Decrypt error: base64ToUint8: " + err);
        return "[Corrupted data]";
    }
    const dec = new TextDecoder();
    let pos = 0;
    let result = '';

    while (pos < data.length) {
        if (pos + 4 + IV_SIZE > data.length) {
            console.error('Corrupted data: incomplete header');
            return '[Corrupted data]'; // строку НЕ изменять!
        }

        const dv = new DataView(data.buffer, pos, 4);
        const chunkLen = dv.getUint32(0, false);
        pos += 4;

        const iv = data.slice(pos, pos + IV_SIZE);
        pos += IV_SIZE;

        const ciphertext = data.slice(pos, pos + chunkLen);
        pos += chunkLen;

        let decrypted = '';
        try {
            decrypted = await crypto.subtle.decrypt(
                {name: "AES-GCM", iv},
                key,
                ciphertext
            );
            result += dec.decode(decrypted);
        } catch (err) {
            console.error("Decrypt error: Corrupted data / invalid key");
            decrypted = "[Corrupted data / invalid key]"; // строку НЕ изменять!
            result += decrypted;
        }

    }

    return result;
}

// === Создание подписи запроса ===
async function makeSignature(operation, timestamp, data, myLogin = '', mySecretKey = '') {
    let extra = '';

    if (!myLogin) myLogin = login;
    if (!mySecretKey) mySecretKey = secretKey;

    // Добавим в подпись параметры id и query, если они присутствуют в запросе
    if (data && typeof data === 'object') {
        const parts = [];
        if (data.id) parts.push('id=' + data.id);
        if (data.query) parts.push('query=' + data.query);
        if (data.title) parts.push('title=' + data.title);
        if (data.rtitle) parts.push('rtitle=' + data.rtitle);
        if (data.tags) parts.push('tags=' + data.tags);
        if (data.rtags) parts.push('rtags=' + data.rtags);
        if (data.text) parts.push('text=' + data.text);
        if (parts.length) extra = ':' + parts.join(':');
    }

    let base = `${myLogin}:${timestamp}:${operation}:${mySecretKey}${extra}`;
    let mySign = await sha256(base);
    if (debugIsOn === true) document.getElementById('debug').textContent += "\nmakeSignature => " + base + " " + mySign + "\n";
    return mySign;
}

// === AJAX ===
async function sendRequest(operation, data, apiUrl, login, mySecretKey = '') {
    if (debugIsOn) console.log(`sendRequest('${operation}',...)`);
    const timestamp = Math.floor(Date.now() / 1000);
    const sign = await makeSignature(operation, timestamp, data, login, mySecretKey);
    const payload = {login, timestamp, operation, sign, ...(data || {})};
    if (debugIsOn === true) document.getElementById('debug').textContent += "\nЗапрос => " + JSON.stringify(payload, null, 2) + "\n";
    let res;
    try {
        res = await fetch(apiUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
    } catch (e) {
        return {ok: false, error: "request_failed", msg: `Request to server ${apiUrl} failed `};
    }
    const text = await res.text();
    if (debugIsOn === true) document.getElementById('debug').textContent += "\nОтвет <= " + text + "\n";
    try {
        return JSON.parse(text);
    } catch (e) {
        console.warn('Invalid JSON response:', text.slice(0, 300) + '...');
        return {ok: false, error: "invalid_json", msg: "Invalid server response"};
    }
}

function bbcodeToHtml(input) {
    if (!input) return "";

    // 0. Экранируем HTML для защиты от XSS
    let text = input
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    // 1. Переводы строк → <br>\n
    text = text.replace(/\r?\n/g, "<br>\n");

    // 2. Преобразуем http/https в ссылки, кроме тех, что внутри [url=...]
    text = text.replace(
        /(?<!\[url=)(https?:\/\/[^\s<>\]\[]*?)([.,)]?)(?=$|\s|<|>|,|\)|])/gi,
        (match, url, punct) => {
            // Если последним символом URL является точка или запятая — выносим её за ссылку
            const lastChar = url.slice(-1);
            if (/[.,]/.test(lastChar)) {
                url = url.slice(0, -1);
                return `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>${lastChar}${punct}`;
            } else {
                return `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>${punct}`;
            }
        }
    );

    // 3. Замены PHPBB тегов
    // noinspection HtmlUnknownTarget,HtmlUnknownAnchorTarget
    const replacements = [
        {re: /\[b](.*?)\[\/b]/gis, to: "<b>$1</b>"},
        {re: /\[i](.*?)\[\/i]/gis, to: "<i>$1</i>"},
        {re: /\[u](.*?)\[\/u]/gis, to: "<u>$1</u>"},
        {re: /\[s](.*?)\[\/s]/gis, to: "<s>$1</s>"},
        {re: /\[hr]/gi, to: "<hr>"},
        {re: /\[ol](.*?)\[\/ol]/gis, to: "<ol>$1</ol>"},
        {re: /\[ul](.*?)\[\/ul]/gis, to: "<ul>$1</ul>"},
        {re: /\[li](.*?)\[\/li]/gis, to: "<li>$1</li>"},
        {re: /\[code](.*?)\[\/code]/gis, to: "<code>$1</code>"},
        {re: /\[quote](.*?)\[\/quote]/gis, to: "<pre>$1</pre>"},
        {
            re: /\[url=([^\]]+)](.*?)\[\/url]/gis,
            to: '<a href="$1" target="_blank" rel="noopener noreferrer">$2</a>'
        },
        {
            re: /\[link=([^\]]+)](.*?)\[\/link]/gis,
            to: '<a href="$1" target="_blank" rel="noopener noreferrer">$2</a>'
        },
        {
            re: /\[url=#([0-9]+)](.*?)\[\/url]/gis,
            to: '<a href="#$1" data-id="$1" class="internal-link">$2</a>'
        }
    ];

    for (const {re, to} of replacements) {
        text = text.replace(re, to);
    }

    return text;
}

// === Универсальный autocomplete для тегов по ID ===
function initTagAutocomplete(inputId) {
    const inputElem = document.getElementById(inputId);
    if (!inputElem) {
        console.warn(`initTagAutocomplete: элемент с ID "${inputId}" не найден`);
        return;
    }

    let suggestionBox = document.createElement('div');
    suggestionBox.className = 'autocomplete-box';
    suggestionBox.id = 'autocomplete-'+inputId;
    document.body.appendChild(suggestionBox);

    let activeIndex = -1; // индекс текущего выделенного элемента
    let currentSuggestions = [];

    function positionBox() {
        const rect = inputElem.getBoundingClientRect();
        suggestionBox.style.left = rect.left + window.scrollX + 'px';
        suggestionBox.style.top = rect.bottom + window.scrollY + 'px';
        suggestionBox.style.width = rect.width + 'px';
    }

    // --- Кеш для autocomplete ---
    const TAG_CACHE = new Map(); // key -> {time, data}
    const TAG_CACHE_TTL = 10_000; // 10 секунд
    const TAG_CACHE_MAX = 100;

// Получение из кеша
    function tagCacheGet(key) {
        const item = TAG_CACHE.get(key);
        if (!item) return null;

        // проверка TTL
        if (Date.now() - item.time > TAG_CACHE_TTL) {
            TAG_CACHE.delete(key);
            return null;
        }

        // LRU — перенос в конец
        TAG_CACHE.delete(key);
        TAG_CACHE.set(key, item);

        return item.data;
    }

// Запись в кеш
    function tagCacheSet(key, data) {
        TAG_CACHE.set(key, {time: Date.now(), data});

        // ограничиваем размер
        if (TAG_CACHE.size > TAG_CACHE_MAX) {
            // удаляем самый старый ключ (первый в Map)
            const firstKey = TAG_CACHE.keys().next().value;
            TAG_CACHE.delete(firstKey);
        }
    }

    async function fetchTags(fragment) {
        if (!fragment || fragment.length < 3 || fragment.length > 15) return [];

        const cached = tagCacheGet(fragment);
        if (cached) return cached;

        try {
            const encQuery = await ENC.encodeForIndex(fragment);
            const res = await sendRequest('gettags', {query: encQuery}, apiUrl, login, secretKey);

            const encryptedTagsList = Array.isArray(res) ? res :
                (res && Array.isArray(res.tags) ? res.tags : []);

            const lowerFragment = fragment.trim().toLowerCase();
            const matchedTags = new Map();

            for (const encTag of encryptedTagsList) {
                try {
                    const decrypted = await decryptText(encTag, aesKey);
                    const tags = decrypted.split(/[, ]+/).map(t => t.trim()).filter(Boolean);

                    for (const tag of tags) {
                        const tagLower = tag.toLowerCase();
                        if (tagLower.includes(lowerFragment) && !matchedTags.has(tagLower)) {
                            matchedTags.set(tagLower, tag);
                        }
                    }
                } catch {
                }
            }

            const result = Array.from(matchedTags.values());

            tagCacheSet(fragment, result);

            return result;

        } catch (e) {
            console.error('Ошибка autocomplete:', e);
            return [];
        }
    }


    async function onInput() {
        const value = inputElem.value;
        const parts = value.split(/[ ,]/).map(s => s.trim());
        const last = parts[parts.length - 1] || '';
        if (last.length < 3) {
            suggestionBox.style.display = 'none';
            return;
        }
        const suggestions = await fetchTags(last);
        currentSuggestions = suggestions;
        activeIndex = -1;
        renderSuggestions(suggestions);
    }

    function renderSuggestions(list) {
        suggestionBox.innerHTML = '';
        if (!list.length) {
            suggestionBox.style.display = 'none';
            return;
        }

        list.forEach((tag, index) => {
            const item = document.createElement('div');
            item.className = 'autocomplete-item';
            item.textContent = tag;
            item.addEventListener('mousedown', e => {
                e.preventDefault();
                selectTag(tag);
            });
            if (index === activeIndex) item.classList.add('active');
            suggestionBox.appendChild(item);
        });

        positionBox();
        suggestionBox.style.display = 'block';
    }

    function selectTag(tag) {
        const parts = inputElem.value.split(/[ ,]/).map(s => s.trim());
        parts[parts.length - 1] = tag;
        inputElem.value = parts.filter(Boolean).join(', ') + ', ';
        suggestionBox.style.display = 'none';
        inputElem.focus();
    }

    // === управление клавиатурой ===
    function onKeyDown(e) {
        const items = suggestionBox.querySelectorAll('.autocomplete-item');
        if (!items.length || suggestionBox.style.display === 'none') return;

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                activeIndex = (activeIndex + 1) % items.length;
                updateActiveItem(items);
                scrollToActive(inputId);
                break;
            case 'ArrowUp':
                e.preventDefault();
                activeIndex = (activeIndex - 1 + items.length) % items.length;
                updateActiveItem(items);
                scrollToActive(inputId);
                break;
            case 'Enter':
                if (activeIndex >= 0 && activeIndex < currentSuggestions.length) {
                    e.preventDefault();
                    selectTag(currentSuggestions[activeIndex]);
                }
                break;
            case 'Escape':
                suggestionBox.style.display = 'none';
                activeIndex = -1;
                break;
        }
    }

    function updateActiveItem(items) {
        items.forEach((item, i) => {
            item.classList.toggle('active', i === activeIndex);
        });
    }

    inputElem.addEventListener('input', onInput);
    inputElem.addEventListener('keydown', onKeyDown);
    inputElem.addEventListener('blur', () => setTimeout(() => suggestionBox.style.display = 'none', 150));
    window.addEventListener('resize', positionBox);

    // Убираем подсказки при сабмите формы
    inputElem.form?.addEventListener('submit', () => {
        suggestionBox.style.display = 'none';
        suggestionBox.innerHTML = '';
    });
}

/**
 * Прокручивает автокомплит, чтобы активный элемент был видимым
 * @param {string} inputId - ID input'а (для поиска .autocomplete-box)
 */
// В main.js, обновите scrollToActive с логами
function scrollToActive(inputId) {

    const boxId = `autocomplete-${inputId}`; // Уникальный ID, как в initTagAutocomplete
    const box = document.getElementById(boxId);

    if (!box) {
        return;
    }

    const activeLi = box.querySelector('div.active');

    if (!activeLi) {
        return;
    }

    // Расчёт позиции (относительно box)
    const boxRect = box.getBoundingClientRect();
    const liRect = activeLi.getBoundingClientRect();
    const scrollTop = box.scrollTop;
    const boxHeight = box.clientHeight;
    const liTopRelative = liRect.top - boxRect.top + scrollTop; // Относительная позиция li
    const liHeight = liRect.height;

    // Прокрутка: если li вне viewport box — центрируем
    if (liTopRelative < scrollTop) {
        // Слишком высоко
        box.scrollTop = liTopRelative - (boxHeight / 3); // 1/3 сверху для плавности
    } else if (liTopRelative + liHeight > scrollTop + boxHeight) {
        // Слишком низко
        box.scrollTop = liTopRelative + liHeight - (boxHeight * 2 / 3); // 2/3 снизу
    }
}

function formatTags(tagsString, myClass = 'tag-label') {
    if (!tagsString) return "";

    // Удаляем потенциально опасные символы
    const safeString = tagsString.replace(/[<>"']/g, "");

    // Разделяем по запятым или пробелам
    const tags = safeString
        .split(/[\s,]+/)
        .map(t => t.trim())
        .filter(t => t.length > 0);

    // Формируем HTML
    return tags.map(tag => `<span class="${myClass}">${tag}</span>`).join("");
}

function formatMySQLDate(date_m) {
    if (!date_m) return '';
    const d = new Date(date_m);

    return new Intl.DateTimeFormat('ru-RU', {
        day: '2-digit',
        month: 'long',
        year: 'numeric'
    }).format(d);
}

function formatDate(strDateTime, format) {
    if (!strDateTime) return '';
    const date = new Date(strDateTime.replace(" ", "T"));
    const pad = (n) => (n < 10 ? '0' + n : n);

    const map = {
        Y: date.getFullYear(),
        y: date.getFullYear().toString().slice(2),
        m: pad(date.getMonth() + 1),
        d: pad(date.getDate()),
        H: pad(date.getHours()),
        i: pad(date.getMinutes()),
        s: pad(date.getSeconds()),
    };

    return format.replace(/[YymdHis]/g, (m) => map[m]);
}

function initInternalLinks() {
    // Находим все ссылки с классом internal-link
    const links = document.querySelectorAll('a.internal-link');
    links.forEach(link => {
        // Сначала снимаем возможный старый обработчик (на случай повторной инициализации)
        link.removeEventListener('click', handleInternalClick);
        link.addEventListener('click', handleInternalClick);
    });
}

async function handleInternalClick(e) {
    e.preventDefault();
    const id = parseInt(this.dataset.id, 10);
    if (!isNaN(id)) {
        await viewNote(id);
    }
}

function setHash(value) {
    if (!saveHistory) return; // Ничего не делаем если запись истории отключена
    if (value === '' || value === null) {
        history.pushState(null, '', window.location.pathname + window.location.search);
    } else {
        history.pushState(null, '', '#' + value);
    }
}

// WYSIWYG editor
function makeWysiwyg(id) {
    //alert('debug: makeWysiwyg '+id);
    const textarea = document.getElementById(id);
    if (!textarea) return;
    if (textarea.dataset.wysiwygInit === "1") destroyWysiwyg(id);
    textarea.dataset.wysiwygInit = "1";

    const wrapper = document.createElement('div');
    wrapper.className = 'wysiwyg-wrapper';

    const toolbar = document.createElement('div');
    toolbar.className = 'wysiwyg-toolbar';
    const buttons = [
        {label: '<b>B</b>', tag: 'b'},
        {label: '<i>I</i>', tag: 'i'},
        {label: '<u>U</u>', tag: 'u'},
        {label: '<s>S</s>', tag: 's'},
        {label: '🔢', tag: 'olblock'},
        {label: '⊡', tag: 'ulblock'},
        {label: '🔗', tag: 'url'},
        {label: '―', tag: 'hr', single: 'true'},
        {label: '#', tag: 'code'},
        {label: '❏️', tag: 'quote'},
        {label: '⌘', mode: 'source'}
    ];

    let b = document.createElement('button');
    b.innerHTML = '?';
    b.classList.add('hidden');
    toolbar.appendChild(b);
    b.onclick = () => {
        return false;
    }


    buttons.forEach(btn => {
        const b = document.createElement('button');
        b.type = 'button';
        b.innerHTML = btn.label;
        Object.assign(b.dataset, btn);
        toolbar.appendChild(b);
    });

    const editable = document.createElement('div');
    editable.className = 'wysiwyg-editor';
    editable.contentEditable = 'true';
    editable.tabIndex = 3;
    editable.innerHTML = bbToHtml(textarea.value || textarea.textContent || '');

    // вставляем
    textarea.parentNode.replaceChild(wrapper, textarea);
    wrapper.append(toolbar, editable, textarea);
    textarea.classList.add('hidden');

    let sourceMode = false;

    // ========================
    // === обработка кнопок ===
    // ========================
    toolbar.addEventListener('mousedown', e => e.preventDefault());
    toolbar.addEventListener('click', e => {
        const btn = e.target.closest('button');
        if (!btn) return;

        const {tag, insert, mode} = btn.dataset;

        if (mode === 'source') {
            sourceMode = !sourceMode;
            if (sourceMode) {
                // === в текстовый режим ===
                const html = editable.innerHTML
                    .replace(/<div><br><\/div>/g, '\n')
                    .replace(/<div>/g, '\n')
                    .replace(/<\/div>/g, '')
                    .replace(/<br\s*\/?>/gi, '\n');
                textarea.value = bbFromHtml(html);
                editable.classList.add('hidden');
                textarea.classList.remove('hidden');
                btn.textContent = '✨';
            } else {
                // === обратно в визуальный ===
                const bbText = textarea.value.replace(/\r\n?/g, '\n');
                editable.innerHTML = bbToHtml(bbText);
                textarea.classList.add('hidden');
                editable.classList.remove('hidden');
                btn.textContent = '⌘';
            }

            return;
        }


        if (sourceMode) {
            insertTagToTextarea(tag, insert);
            return;
        }

        editable.focus();
        if (tag) {
            if (tag === 'hr') {
                insertSingle(tag);
            } else if (tag === 'url') {
                insertLink();
            } else if (tag === 'quote') {
                insertQuote();
            } else if (tag === 'olblock') {
                insertListBlock('ol');
            } else if (tag === 'ulblock') {
                insertListBlock('ul');
            } else {
                toggleTag(tag);
            }
        } else if (insert) {
            insertPlain(insert);
        }
    });

    function insertLink() {
        const sel = window.getSelection();
        if (!sel.rangeCount) return;
        const range = sel.getRangeAt(0);
        const text = sel.toString();
        const url = prompt('Введите ссылку:', text.startsWith('http') ? text : 'https://');
        if (!url) return;

        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.textContent = text || url;

        range.deleteContents();
        range.insertNode(a);

        // установить курсор после ссылки
        range.setStartAfter(a);
        range.setEndAfter(a);
        sel.removeAllRanges();
        sel.addRange(range);
    }

    function insertListBlock(type) {
        const sel = window.getSelection();

        if (sourceMode) {
            // режим plain text (BB-коды)
            const start = textarea.selectionStart;
            const text = textarea.value;

            const tpl =
                `[${type}]\n` +
                `[li][/li]\n` +
                `[li][/li]\n` +
                `[li][/li]\n` +
                `[/${type}]\n`;

            textarea.value = text.slice(0, start) + tpl + text.slice(start);
            textarea.selectionStart = textarea.selectionEnd = start + tpl.length;
            textarea.focus();
            return;
        }

        // режим WYSIWYG
        const range = sel.rangeCount ? sel.getRangeAt(0) : null;
        if (!range) return;

        const list = document.createElement(type);
        list.innerHTML =
            "<li></li><li></li><li></li>";

        range.deleteContents();
        range.insertNode(list);

        // ставим курсор внутрь первого li
        const firstLi = list.querySelector("li");
        if (firstLi) {
            const r = document.createRange();
            r.selectNodeContents(firstLi);
            r.collapse(true);
            sel.removeAllRanges();
            sel.addRange(r);
        }
    }


    function insertQuote() {
        const sel = window.getSelection();
        if (!sel.rangeCount) return;
        const range = sel.getRangeAt(0);
        const text = sel.toString() || 'Текст цитаты';

        const block = document.createElement('pre');
        block.textContent = text;

        range.deleteContents();
        range.insertNode(block);

        // поставить курсор после цитаты
        range.setStartAfter(block);
        range.setEndAfter(block);
        sel.removeAllRanges();
        sel.addRange(range);
    }

    function insertSingle(tag) {
        if (sourceMode) {
            // plain text mode
            const start = textarea.selectionStart;
            const text = textarea.value;
            const rep = `[${tag}]`;
            textarea.value = text.slice(0, start) + rep + text.slice(start);
            textarea.selectionStart = textarea.selectionEnd = start + rep.length;
            textarea.focus();
        } else {
            // wysiwyg mode
            const range = window.getSelection().getRangeAt(0);
            const hr = document.createElement('hr');
            range.insertNode(hr);

            const next = hr.nextSibling;
            if (next && next.nodeType === 1 && next.nodeName === 'BR') {
                next.parentNode.removeChild(next);
            }

            range.setStartAfter(hr);
            range.setEndAfter(hr);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
        }
    }

    function toggleTag(tag) {
        const sel = window.getSelection();
        if (!sel.rangeCount) return;
        const range = sel.getRangeAt(0);

        // Если есть выделение — оборачиваем как раньше
        if (!sel.isCollapsed) {
            const ancestor = getAncestorWithTag(sel.focusNode, tag);
            if (ancestor) {
                unwrap(ancestor);
            } else {
                const el = document.createElement(tag);
                el.appendChild(range.extractContents());
                range.insertNode(el);
                sel.removeAllRanges();
                const r = document.createRange();
                r.selectNodeContents(el);
                sel.addRange(r);
            }
            return;
        }

        // === если выделения нет — используем execCommand ===
        // execCommand устарел, но идеально подходит для contentEditable
        editable.focus();
        if (tag === 'b') document.execCommand('bold');
        else if (tag === 'i') document.execCommand('italic');
        else if (tag === 'u') document.execCommand('underline');
        else if (tag === 's') document.execCommand('strikeThrough');
    }


    function getAncestorWithTag(node, tag) {
        while (node && node !== editable) {
            if (node.nodeType === 1 && node.tagName.toLowerCase() === tag) return node;
            node = node.parentNode;
        }
        return null;
    }

    function unwrap(node) {
        const parent = node.parentNode;
        while (node.firstChild) parent.insertBefore(node.firstChild, node);
        parent.removeChild(node);
    }

    // ===========================
    // === вставка BB в plain ====
    // ===========================
    function insertTagToTextarea(tag, insert) {
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const text = textarea.value;
        const sel = text.slice(start, end);
        let rep = '';

        if (tag) {
            if (tag) {
                if (tag === 'olblock') {
                    rep =
                        `[ol]\n` +
                        `[li][/li]\n` +
                        `[li][/li]\n` +
                        `[li][/li]\n` +
                        `[/ol]\n`;
                } else if (tag === 'ulblock') {
                    rep =
                        `[ul]\n` +
                        `[li][/li]\n` +
                        `[li][/li]\n` +
                        `[li][/li]\n` +
                        `[/ul]\n`;
                } else if (tag === 'url') {
                    const url = prompt('Введите ссылку:');
                    if (!url) return;
                    rep = `[url=${url}]${sel}[/url]`;
                } else if (tag === 'hr') {
                    rep = `[hr]\n`;
                } else {
                    rep = `[${tag}]${sel}[/${tag}]`;
                }
            }
        } else if (insert) {
            if (insert.includes('][') && sel) {
                const [open, close] = insert.split('][');
                rep = `${open}]${sel}[${close}`;
            } else rep = insert;
        }

        textarea.value = text.slice(0, start) + rep + text.slice(end);
        textarea.focus();
        textarea.selectionStart = textarea.selectionEnd = start + rep.length;
    }

    // =======================
    // === вставка простого текста ===
    // =======================
    function insertPlain(text) {
        const range = window.getSelection().getRangeAt(0);
        range.deleteContents();
        range.insertNode(document.createTextNode(text));
        range.collapse(false);
    }

    // =======================
    // === поведение фокуса ===
    // =======================
    editable.addEventListener('mousedown', e => {
        // просто ставим фокус, ничего не вставляем
        if (e.button === 0) {
            e.stopPropagation();
            editable.focus();
        }
    });

    editable.addEventListener('mouseup', e => {
        e.stopPropagation();
        editable.focus();
    });

    // конвертеры BB↔HTML
    function bbToHtml(bb) {
        //alert('debug: bbToHtml '+bb);
        // noinspection HtmlUnknownTarget
        return bb
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\r\n?/g, '\n')
            .replace(/\[url=(.*?)](.*?)\[\/url]/gi, '<a href="$1" target="_blank">$2</a>')
            .replace(/\[link=(.*?)](.*?)\[\/link]/gi, '<a href="$1" target="_blank">$2</a>')
            .replace(/\[quote](.*?)\[\/quote]/gis, '<pre>$1</pre>')
            .replace(/\[code](.*?)\[\/code]/gis, '<code>$1</code>')
            .replace(/\n*\[ol]\n*/gi, '<ol>').replace(/\n*\[\/ol]\n*/gi, '</ol>')
            .replace(/\n*\[ul]\n*/gi, '<ul>').replace(/\n*\[\/ul]\n*/gi, '</ul>')
            .replace(/\[li]/gi, '<li>').replace(/\[\/li]\n?/gi, '</li>')
            .replace(/\[b]/gi, '<b>').replace(/\[\/b]/gi, '</b>')
            .replace(/\[i]/gi, '<i>').replace(/\[\/i]/gi, '</i>')
            .replace(/\[u]/gi, '<u>').replace(/\[\/u]/gi, '</u>')
            .replace(/\[s]/gi, '<s>').replace(/\[\/s]/gi, '</s>')
            .replace(/\s*\[hr]\s*\n?/gi, '<hr>')
            .replace(/\n/g, '<br>');
    }


    function bbFromHtml(html) {
        //alert('debug: bbFromHtml '+html);
        let out = html
            .replace(/\r\n?/g, '\n')
            .replace(/<div><br><\/div>/gi, '\n')
            .replace(/<div>/gi, '\n')
            .replace(/<\/div>/gi, '')
            .replace(/<hr[^>]*>\s*(?:<br\s*\/?>|\n|\r\n?)+/gi, '<hr>')
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<ol>/gi, '\n[ol]\n').replace(/<\/ol>/gi, '[/ol]\n\n')
            .replace(/<ul>/gi, '\n[ul]\n').replace(/<\/ul>/gi, '[/ul]\n\n')
            .replace(/<li>/gi, '[li]').replace(/<\/li>/gi, '[/li]\n')
            .replace(/<b>/gi, '[b]').replace(/<\/b>/gi, '[/b]')
            .replace(/<i>/gi, '[i]').replace(/<\/i>/gi, '[/i]')
            .replace(/<u>/gi, '[u]').replace(/<\/u>/gi, '[/u]')
            .replace(/<s>/gi, '[s]').replace(/<\/s>/gi, '[/s]')
            .replace(/<a href="(.*?)".*?>(.*?)<\/a>/gi, '[url=$1]$2[/url]')
            .replace(/<pre>(.*?)<\/pre>/gis, '[quote]$1[/quote]')
            .replace(/<code>(.*?)<\/code>/gis, '[code]$1[/code]')
            .replace(/<hr[^>]*>/gi, '\n[hr]\n')
            .replace(/<\/?[^>]+>/g, ''); // убрать остаточные теги

        out = out
            .replace(/&nbsp;/gi, ' ')
            .replace(/&amp;/gi, '&')
            .replace(/&lt;/gi, '<')
            .replace(/&gt;/gi, '>');

        return out;
    }

    function postProcess(bb) {
        return bb
            .replace(/\r\n?/g, '\n')
            .replace(/\[li]/gi, '[li]').replace(/\[\/li]\n*/gi, '[/li]')
            .replace(/\n?\[ol]\n*/gi, '[ol]').replace(/\n*\[\/ol]\n?/gi, '[/ol]')
            .replace(/\n?\[ul]\n*/gi, '[ul]').replace(/\n*\[\/ul]\n?/gi, '[/ul]');
    }

    // Cинхронизация wysiwyg -> textarea при отправке формы
    const form = textarea.closest('form');
    if (form) {
        const handler = () => {
            //alert('debug: form submit action');
            const isVisible = !textarea.classList.contains('hidden');
            if (!isVisible) {
                textarea.value = bbFromHtml(editable.innerHTML);
            }
            textarea.value = postProcess(textarea.value);
        };
        // сохраняем обработчик для последующего удаления
        textarea._wysiwygSubmitHandler = handler;
        form.addEventListener('submit', handler, {capture: true});
    }
}

function destroyWysiwyg(id) {
    //alert('debug: destroyWysiwyg ' + id);
    const textarea = document.getElementById(id);
    if (!textarea || !textarea.dataset.wysiwygInit) return;
    //alert('debug: destroyWysiwyg DONE');

    // УДАЛЯЕМ обработчик submit
    const form = textarea.closest('form');
    if (form && textarea._wysiwygSubmitHandler) {
        form.removeEventListener('submit', textarea._wysiwygSubmitHandler, {capture: true});
        delete textarea._wysiwygSubmitHandler;
    }

    const wrapper = textarea.closest('.wysiwyg-wrapper');
    if (wrapper) wrapper.parentNode.replaceChild(textarea, wrapper);

    textarea.classList.remove('hidden');
    delete textarea.dataset.wysiwygInit;
}

function showError(prefix, data) {
    let error_message = prefix + ': Unknown error';
    if (data && typeof data === 'object' && data.error) {
        if (!data.msg) {
            data.msg = data.error;
        }

        if (data.error === 'timestamp_out_of_range') {
            error_message = data.msg + '\n\nВаше системное время сильно отличается (спешит или отстает) от времени на сервере. Проверьте дату и выполните синхронизацию времени';
        } else if (data.error === 'internal_error' && prefix === 'SQL error') {
            error_message = `Произошла внутренняя ошибка сервера: ${data.msg}. Попробуйте еще раз, если ошибка повторится - нужно обращаться к администратору сервера`;
        } else if (data.error === 'internal_error') {
            error_message = `Произошла внутренняя ошибка сервера: ${data.msg}`;
        } else if (data.error === 'missing_param') {
            if (!data.param) data.param = data.msg;
            error_message = `В вашем запросе отсутствует обязательный параметр: ${data.param}`;
        } else if (data.error === 'too_many_requests') {
            let latter = (data.retry_after) ? `${data.retry_after} сек.` : 'какое-то время';
            error_message = `Количество запросов с вашего IP превышает установленные сервером ограничения.\n\n Пожалуйста, повторите попытку через ${latter}`;
        } else if (data.error === 'bad_signature') {
            error_message = `Сервер отказал в выполнении операции - не верная подпись запроса. Убедитесь, что на сервере сохранен правильный секретный ключ`;
        } else if (data.error === 'request_failed') {
            error_message = prefix + ': ' + 'Сетевая ошибка, не удалось выполнить запрос к серверу (DNS, SSL, сервер не доступен и т.д.).\n\nПопробуйте еще раз попозже, если ошибка повторяется - попробуйте подключиться к резервному серверу (в настройках)';
        } else if (data.error === 'unknown_operation') {
            error_message = `Запрошена не известная серверу операция. Проверьте параметр operation в вашем запросе`;
        } else if (data.error === 'invalid_json') {
            error_message = prefix + ': API сервер вернул не корректный JSON.\n\nВозможные причины ошибки:\n - внутренняя ошибка API сервера\n - не правильные настройки его хостинга\n - у вас в настройках указан не верный адрес API сервера';
        } else if (data.error === 'not_found' && prefix === 'get') {
            error_message = `Запрошенная заметка не найдена на сервере`;
        } else if (data.error === 'not_found' && prefix === 'modify') {
            error_message = `Не удалось сохранить изменения: заметка с указанным вами ID не найдена`;
        } else if (data.error === 'not_found' && prefix === 'delete') {
            error_message = `Удаление не удалось: заметка с указанным вами ID не найдена`;
        } else {
            error_message = prefix + ': ' + data.msg;
        }
    }
    alert(error_message);
}

function initPasswordToggles() {
    // Находим ВСЕ элементы, которые являются кнопками "показать пароль"
    const toggles = document.querySelectorAll('[data-toggle]');

    toggles.forEach(toggle => {
        const targetId = toggle.dataset.toggle;
        const input = document.getElementById(targetId);
        if (!input) return;

        // Функции показать/спрятать
        const show = () => input.type = 'text';
        const hide = () => input.type = 'password';

        // Мышь
        toggle.addEventListener('mousedown', show);
        toggle.addEventListener('mouseup', hide);
        toggle.addEventListener('mouseleave', hide);

        // Сенсорные устройства
        toggle.addEventListener('touchstart', e => {
            e.preventDefault();
            show();
        });
        toggle.addEventListener('touchend', hide);
    });
}

async function doSignup(apiUrl, login, secretKey, options = {}) {
    if (options.noConfirm || confirm('Такой пользователь не зарегистрирован на сервере\n\nХотите создать новый аккаунт с указанным ключом?')) {
        /**
         * @typedef {Object} signupResponse
         * @property {{title: string, text: string, tags: string, date_modified: string}} note
         * @property {boolean} ok
         * @property {string} error
         * @property {string} msg
         * @property {string} welcome_message
         */

        /** @type {signupResponse} */
        const res_reg = await sendRequest('signup', {user_secret_key: secretKey}, apiUrl, login, secretKey);
        if (res_reg && typeof res_reg === 'object' && res_reg.ok === true) {
            // Регистрация прошла успешно
            //alert("Регистрация прошла успешно");
            if (res_reg.welcome_message) alert(res_reg.welcome_message);
            if (debugIsOn) console.warn(`Выполнена регистрация на ${apiUrl} как ${login} с ключом ${secretKey}`);
            return true;
        } else {
            // Ошибка регистрации
            if (debugIsOn) console.warn(`Ошибка регистрации на ${apiUrl} как ${login} с ключом ${secretKey}: [${res_reg.error}] ${res_reg.msg}`);
            if (res_reg.error === 'too_many_requests') {
                alert(res_reg.msg);
            } else {
                showError("Ошибка регистрации", res_reg);
            }
            return false;
        }
    } else {
        // Пользователь не хочет регистрироваться
        if (debugIsOn) console.warn(`Пользователь ${login} отказался регистрироваться на ${apiUrl}`);
        return false
    }
}

async function ungzip(arrayBuffer) {
    // 1) Если браузер поддерживает DecompressionStream
    if ('DecompressionStream' in window) {
        const ds = new DecompressionStream("gzip");
        const decompressed = new Response(
            new Blob([arrayBuffer]).stream().pipeThrough(ds)
        );
        return await decompressed.text();
    }

    // 2) Fallback: минимальный inflate-декодер (raw DEFLATE)
    // Реализуем распаковку gz вручную:
    return ungzipFallback(arrayBuffer);
}


// ---------------------------
// Fallback для браузеров без DecompressionStream
// (минимальная реализация inflate + gzip header parser)
// ---------------------------
function ungzipFallback(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);

    // ---- Парсим заголовок GZIP ----
    if (bytes[0] !== 0x1F || bytes[1] !== 0x8B) {
        throw new Error("Not a valid GZIP file");
    }

    let pos = 10; // пропускаем базовый заголовок gzip

    const FLG = bytes[3];

    if (FLG & 4) { // FEXTRA
        const xlen = bytes[pos] | (bytes[pos + 1] << 8);
        pos += 2 + xlen;
    }
    if (FLG & 8) { // FNAME
        // noinspection StatementWithEmptyBodyJS
        while (bytes[pos++] !== 0) ;
    }
    if (FLG & 16) { // FCOMMENT
        // noinspection StatementWithEmptyBodyJS
        while (bytes[pos++] !== 0) ;
    }
    if (FLG & 2) { // FHCRC
        pos += 2;
    }

    // ---- DEFLATE блок (тело) ----
    const compressedData = bytes.subarray(pos, bytes.length - 8);

    // ---- Мини-инфлейтер ----
    const decompressed = tinyInflate(compressedData);

    // Преобразуем байты -> строку
    return new TextDecoder("utf-8").decode(decompressed);
}


// ---------------------------
// Минимальный inflate-декодер (raw DEFLATE)
// ---------------------------
function tinyInflate(input) {
    // Наиболее компактная JS-реализация inflate.
    // Это адаптация публичного кода (немного сокращена).
    // Работает со всеми DEFLATE потоками.
    function error(e) {
        throw new Error(e);
    }

    let ip = 0, out = [];

    function readBit() {
        let r = (input[ip >> 3] >> (ip & 7)) & 1;
        ip++;
        return r;
    }

    function readBits(n) {
        let r = 0;
        for (let i = 0; i < n; i++) r |= readBit() << i;
        return r;
    }

    function readCode(tbl) {
        let code = 0, first = 0, idx = 0;
        for (let len = 1; len <= 15; len++) {
            code |= readBit() << (len - 1);
            let count = tbl.count[len];
            if (code - first < count)
                return tbl.symbol[idx + (code - first)];
            idx += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        error("Invalid Huffman code");
    }

    function buildHuff(lengths) {
        let count = new Array(16).fill(0);
        for (let len of lengths) count[len]++;

        let next = new Array(16).fill(0);
        for (let i = 1; i < 16; i++) next[i] = (next[i - 1] + count[i - 1]) << 1;

        let symbol = new Array(lengths.length);
        for (let i = 0; i < lengths.length; i++) {
            let len = lengths[i];
            if (len) symbol[next[len]++] = i;
        }
        return {count, symbol};
    }

    function inflateBlock() {
        let type = readBits(2);

        if (type === 0) { // uncompressed
            ip = (ip + 7) & ~7;
            let len = input[ip >> 3] | (input[(ip >> 3) + 1] << 8);
            ip += 32;
            for (let i = 0; i < len; i++) out.push(input[(ip >> 3) + i]);
            ip += len << 3;
        } else {
            let litlen, dist;

            if (type === 1) {
                litlen = fixedLitLen;
                dist = fixedDist;
            } else {
                let hlit = readBits(5) + 257;
                let hdist = readBits(5) + 1;
                let hclen = readBits(4) + 4;

                const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                let cl = new Array(19).fill(0);
                for (let i = 0; i < hclen; i++) cl[order[i]] = readBits(3);

                let cltable = buildHuff(cl);
                let lengths = [];
                while (lengths.length < hlit + hdist) {
                    let sym = readCode(cltable);
                    if (sym < 16) {
                        lengths.push(sym);
                    } else if (sym === 16) {
                        let repeat = 3 + readBits(2);
                        let val = lengths[lengths.length - 1];
                        while (repeat--) lengths.push(val);
                    } else if (sym === 17) {
                        let repeat = 3 + readBits(3);
                        while (repeat--) lengths.push(0);
                    } else {
                        let repeat = 11 + readBits(7);
                        while (repeat--) lengths.push(0);
                    }
                }

                litlen = buildHuff(lengths.slice(0, hlit));
                dist = buildHuff(lengths.slice(hlit));
            }

            while (1) {
                let sym = readCode(litlen);
                if (sym < 256) {
                    out.push(sym);
                } else if (sym === 256) {
                    break;
                } else {
                    let lenIndex = sym - 257;
                    let length = LENGTH_BASE[lenIndex] + readBits(LENGTH_EXTRA[lenIndex]);

                    let dsym = readCode(dist);
                    let distance = DIST_BASE[dsym] + readBits(DIST_EXTRA[dsym]);

                    for (let i = 0; i < length; i++) {
                        out.push(out[out.length - distance]);
                    }
                }
            }
        }
    }

    // fixed trees
    const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 0];
    const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

    // fixed litlen + dist
    let fl = new Array(288).fill(0).map((_, i) => i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
    let fd = new Array(32).fill(5);
    let fixedLitLen = buildHuff(fl);
    let fixedDist = buildHuff(fd);

    let final = 0;
    while (!final) {
        final = readBit();
        inflateBlock();
    }

    return new Uint8Array(out);
}

/**
 * Генерирует случайное целое число из указанного диапазона
 * @param min минимальное число диапазона
 * @param max максимальное число диапазона
 * @returns integer
 */
function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function base64encode(str) {
    const bytes = new TextEncoder().encode(str);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64decode(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}

/**
 * Проверка даты последнего бэкапа
 */
async function checkBackupDate() {
    // Проверка при входе: нужно ли предупреждать о бэкапе
    const X = 14; // Порог в днях (для бэкапа и предупреждений)
    const suffix = login.slice(-3);
    const dataChanged = localStorage.getItem('dataChanged_'+suffix);
    if(!dataChanged) {
        return;
    }
    const lastBackupDateStr = localStorage.getItem('lastBackupDate_'+suffix);
    const lastWarningDateStr = localStorage.getItem('lastWarningDate_'+suffix);
    const now = new Date();
    let daysSinceBackup = false;
    let daysSinceWarning = 0;

    if (lastBackupDateStr) {
        const lastBackupDate = new Date(lastBackupDateStr);
        daysSinceBackup = Math.floor((now - lastBackupDate) / (1000 * 60 * 60 * 24));
    }

    if (lastWarningDateStr) {
        const lastWarningDate = new Date(lastWarningDateStr);
        daysSinceWarning = Math.floor((now - lastWarningDate) / (1000 * 60 * 60 * 24));
    }

    if (!lastWarningDateStr || daysSinceWarning > X) {

        const message = (daysSinceBackup === false) ? `Похоже вы еще не создавали бекап данных для этого аккаунта. Хотите создать?`:`Вы создавали последний бекап данных ${daysSinceBackup} дн. назад. Хотите создать новый?`;
        if (confirm(message)) {
            // Инициируем создание бекапа
            switchTo(['loginArea', 'settingsArea', 'actionsArea']);
            document.getElementById('backupBtn').click();
        } else {
            // Пользователь отказался от бекапа, просто фиксируем дату предупреждение
            localStorage.setItem('lastWarningDate_'+suffix, now.toISOString());
        }
    }
}










