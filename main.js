// noinspection JSDeprecatedSymbols

// ============================================================================================================
// ===================== Глобальные переменные ================================================================
// ============================================================================================================

const required_api_version = '1.1'; // Если не совпадает с версией API сервера - будет показано предупреждение
const client_version = '1.1';

let aesKey, textAesKey, secretKey, login, ENC, apiUrl, activeArea; // общие глобальные переменные
let isLoggedIn = false; // флаг, выполнен ли вход
let scorePassphrase = 0; // Стартовый уровень "сложности" введенного секрета
let serverMaxInput = 5 * 1024 * 1024; // Размер максимального запроса к серверу. API с v1.1 передает при логине

// Настройки по умолчанию
let debugIsOn = false;  // по умолчанию отладка выключена
let enableTools = false; // По умолчанию Text Tools отключены
let unsafePassphrase = false; // По умолчанию включена проверка комплексности паролей
let settingSavePassphrase = '0'; // По умолчанию сохранение секрета отключено


// Текстовые ресурсы
const messageStorageUnavailable = 'Похоже локальное хранилище не доступно. Настройка будет работать только до перезагрузки страницы!';
const messagePleaseLoginFirst = 'Ошибка: вход не выполнен!\n\nПеред выполнением этого действия нужно войти на сервер!';

// ============================================================================================================
// ===================== Назначение обработчиков событий ======================================================
// ============================================================================================================

// Показываем иконки при вводе passphrase и обновляем индикатор "надежности" по мере набора секрета
document.getElementById('passphrase').addEventListener('input', async () => {
    await updateSecretIcons(['secretIcons', 'secretIcons2']);
    evaluatePassphrase('passphrase', 'progress');
});

document.getElementById('passphrase2').addEventListener('input', async() => {
    await updateSecretIcons('secretIcons4');
    evaluatePassphrase('passphrase2', 'progress2');

});
document.getElementById('passphrase1').addEventListener('input', async () => {
    await updateSecretIcons('secretIcons3');
});
document.getElementById('enableDebug').addEventListener('change', updateSettingDebug); // Изменение настройки "Включить отладку"
document.getElementById('debugToggle').addEventListener('click', debugToggle); // Сворачивает / разворачивает панель отладки
document.getElementById('unsafePassphrase').addEventListener('change', updateSettingUnsafePassphrase); // Изменение настройки "Разрешить простые фразы"
document.getElementById('enableTools').addEventListener('change', updateSettingTools);
document.getElementById('savePassphrase').addEventListener('change', updateSettingSavePassphrase); // Изменение настройки "Сохранить секретную фразу"
document.getElementById('terminateAccountBtn').addEventListener('click', handlerTerminateAccount); // Account termination
document.getElementById('doDecodeTextBtn').addEventListener('click', handlerDecryptText);  // Decrypt text button
document.getElementById('apiServer').addEventListener('change', updateApiServer); // Сохранение выбранного сервера при изменении
document.getElementById('btnTextArea').addEventListener('click', onBtnTextAreaClick); // Show crypt / decrypt text form
document.getElementById('btnLogout').addEventListener('click', onBtnLogoutClick); // Logout button
document.addEventListener("keydown", escHandler, {capture: true}); // обработка для нажатия ESC

// ============================================================================================================
// ===================== Инициализация. Выполняется разово при загрузке страницы ==============================
// ============================================================================================================

document.getElementById('version').textContent = client_version;

// === Сохранение и загрузка выбранного пользователем сервера
const selectApiServer = document.getElementById('apiServer');
if(selectApiServer) {
    let savedApiServer = localStorageGet('apiServer');
// Проверяем, что бы значение из localStorage было корректным. Если его нет среди options - используем дефолтное, то что selected в options
    if (savedApiServer && [...selectApiServer.options].some(o => o.value === savedApiServer)) {
        selectApiServer.value = savedApiServer;
    } else {
        localStorageSet('apiServer', selectApiServer.value);
    }
    selectApiServer.dispatchEvent(new Event('change', {bubbles: true})); // имитируем событие
}

// === Сохранение и загрузка настройки "Отладка"
debugIsOn = (localStorageGet('enableDebug') === '1'); // восстановим глобальную переменную
document.getElementById('enableDebug').checked = debugIsOn; // установим / снимем галочку в форме настроек
if (debugIsOn) { // покажем форму отладки при загрузке страницы
    document.getElementById('debugToggle').classList.remove('hidden');
}

// === Восстановление настройки "простые пароли"
unsafePassphrase = (localStorageGet('unsafePassphrase') === '1'); // восстановим глобальную переменную
document.getElementById('unsafePassphrase').checked = unsafePassphrase; // установим / снимем галочку в форме настроек

// === Сохранение и загрузка настройки "Включить Text Tools"
enableTools = (localStorageGet('enableTools') === '1'); // восстановим глобальную переменную
document.getElementById('enableTools').checked = enableTools; // установим / снимем галочку в форме настроек
updateSettingTools(); // спрячем / покажем кнопку в зависимости от настроек


// === Пробуем восстановить сохраненный секрет и выполнить автоматический логин
const checkboxSavePassphrase = document.getElementById('savePassphrase');
(async () => {
    settingSavePassphrase = localStorageGet('savePassphrase');
    checkboxSavePassphrase.checked = (settingSavePassphrase === '1');

    let savedPassphrase = sessionStorageGet('passphrase');
    // Если в sessionStorage фразы нет - попробуем расшифровать из localStorage, если включено сохранение
    if (!savedPassphrase && settingSavePassphrase === '1') {
        const enc = localStorageGet("encData");
        if (enc) {
            try {
                /** @type {ArrayBuffer} */
                let bioKey = await getBioKey();
                const aesKey = await crypto.subtle.importKey("raw", bioKey, "AES-GCM", false, ["encrypt", "decrypt"]);
                savedPassphrase = await decryptText(enc, aesKey);
                sessionStorageSet('passphrase', savedPassphrase);
                console.log('debug: passphrase расшифрована и записана в sessionStorage!');
            } catch (e) {
                console.log('debug: ошибка получения ключа');
                // ошибка получения ключа / расшифровки, покажем форму логина
                switchTo('loginArea');
            }
        } else {
            console.log('debug: encData не найден в localStorage!');
        }
    }

    if (savedPassphrase) {
        document.getElementById('passphrase').value = savedPassphrase; // Вставляем фразу в форму
        document.getElementById('passphrase').dispatchEvent(new Event('input', {bubbles: true})); // что бы сработал вызов updateSecretIcons
    }

    console.log('пробуем авто вход');
    // Автоматический вход на случай перезагрузки страницы
    if (savedPassphrase) {
        let passphrase = savedPassphrase;
        evaluatePassphrase('passphrase', 'progress'); // посчитаем "сложность" пароля
        console.log('debug: автоматический логин');
        await doLogin(passphrase, true);
    } else {
        console.log('debug: passphrase не введена, покажем форму логина');
        // покажем форму логина
        switchTo('loginArea');
    }
})();

// Запускаем некоторые функции после загрузки DOM
document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles(); // значки для просмотра паролей
    initTagAutocomplete('searchQuery'); // Подключаем подсказки автозавершения для поиска
    initTagAutocomplete('editTagsInput'); // Подключаем подсказки автозавершения для тегов
});

// ============================================================================================================
// ===================== Функции обработчиков =================================================================
// ============================================================================================================

function updateApiServer() {
    localStorageSet('apiServer', this.value);
    const selectedOption = this.options[this.selectedIndex];
    const computedStyle = window.getComputedStyle(selectedOption);
    this.style.backgroundColor = computedStyle.backgroundColor;
    this.style.color = computedStyle.color;
}
function escHandler(event) {
    if (activeArea === 'viewArea') {
        if (event.key === "Escape") {
            document.getElementById("btnActionClose").click();
            return;
        }
        if (event.key === "Delete") {
            document.getElementById("btnActionDelete").click();
            return;
        }
    }
    if (activeArea === 'helpArea') {
        if (event.key === "Escape") {
            document.getElementById("closeHelpBtn").click();
            return;
        }
    }
    if (activeArea === 'importArea') {
        if (event.key === "Escape") {
            document.getElementById("closeImportBtn").click();
            return;
        }
    }
    if (activeArea === 'exportArea') {
        if (event.key === "Escape") {
            document.getElementById("closeExportBtn").click();
            return;
        }
    }
    if (activeArea === 'passwdArea') {
        if (event.key === "Escape" && document.getElementById("btnCancelPasswd").disabled === false) {
            document.getElementById("btnCancelPasswd").click();
            return;
        }
    }
    if (activeArea === 'loginArea') {
        if (event.key === "Escape" && !document.getElementById("settingsArea").classList.contains('hidden')) {
            updateElements([
                [['settingsArea', 'actionsArea'], 'classList', 'hidden', 'add']
            ]);
            return;
        }
    }
    if (activeArea === 'textArea') {
        if (event.key === "Escape") {
            document.getElementById("closeTextBtn").click();
            return;
        }
    }
    if (activeArea === 'restoreArea') {
        if (event.key === "Escape") {
            document.getElementById("closeRestoreBtn").click();
            return;
        }
    }
    if (activeArea === 'editArea') {
        if (event.key === "Escape") {
            let title = document.getElementById('editTitleInput').value;
            let tags = document.getElementById('editTagsInput').value;
            if ((title === '' && tags === '') || confirm('Закрыть форму?')) {
                document.getElementById("btnCancelEdit").click();
            }
            return;
        }
    }
    if (activeArea === 'searchArea') {
        if (event.key === "Escape") {
            if (document.getElementById('searchResultsList').textContent === '') return;
            const box = document.querySelector('.autocomplete-box');
            if (box && box.style.display !== 'none') {
                return;
            }
            document.getElementById("clearResultLink").click();
            // return; // если есть еще код ниже
        }
    }
}

/**
 * Действие выполняемое для "выхода" из системы
 * удаление сохраненной секретной фразы, ключей, флагов, визуальные изменения в интерфейсе и т.д.
 * @param e
 */
function onBtnLogoutClick(e) {
    e.preventDefault();
    sessionStorageRemove('passphrase');
    localStorageRemove('encData');
    login = false;
    secretKey = false;
    aesKey = false;
    ENC = false;
    isLoggedIn = false;
    updateElements([
        ['passphrase', 'value', ''],
        ['btnLogout', 'classList', 'hidden', 'add'],
        [['passwdBtn', 'exportBtn', 'importBtn', 'backupBtn', 'restoreBtn', 'terminateAccountBtn'], 'disabled', true],
        [['secretIcons', 'secretIcons2', 'secretIcons3'], 'textContent', ''],
        ['progress', 'style.width', '0%'],
    ]);
}

async function handlerDecryptText(e) {
    e.preventDefault();
    const area = document.getElementById('encodeTextArea');
    if (area.value === '') {
        return;
    }
    const decryptedText = await decryptText(area.value, textAesKey);
    if (decryptedText === '[Corrupted data / invalid key]') {
        alert('Указанная секретная фраза не подходит для расшифровки этого текста!');
        return;
    } else if (decryptedText === '[Corrupted data]') {
        alert('Ошибка, похоже текст для расшифровки поврежден!');
        return;
    }
    area.value = decryptedText;
}

/**
 *
 * @returns {Promise<void>}
 */
async function handlerTerminateAccount(event) {
    event.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    if (confirm('Удаление аккаунта\n\nВы собираетесь безвозвратно удалить все ваши записи и регистрацию на сервере\n\nЭто действие не может быть отменено, все данные будут удалены без возможности восстановления\n\n\nХотите продолжить?')) {
        if (confirm('Последнее предупреждение. Вы уверены?')) {
            const res = await sendRequest('terminate', {}, apiUrl, login, secretKey);
            if (res && typeof res === 'object' && res.ok === true) {
                alert('Ваша регистрация и все данные удалены с сервера');
                localStorageRemove('dataChanged_' + login.slice(-3));
                localStorageRemove('lastBackupDate_' + login.slice(-3));
                localStorageRemove('lastWarningDate_' + login.slice(-3));
            } else {
                showError('Удаление данных', res);
            }
        }
    }
}

/**
 * Устанавливает глобальную переменную settingSavePassphrase, инициирует активацию биометрии, охраняет полученный credId и записывает настройку в localStorage
 * Сама фраза шифруется и сохраняется только по doLogin()
 * @returns {Promise<void>}
 */
async function updateSettingSavePassphrase() {
    settingSavePassphrase = (this.checked) ? '1' : '0';
    if (!localStorageSet('savePassphrase', settingSavePassphrase)) {
        alert('Локальное хранилище не доступно, сохранить фразу не получится!');
        settingSavePassphrase = 0;
        checkboxSavePassphrase.checked = false;
        checkboxSavePassphrase.disabled = true;
    }

    if (settingSavePassphrase === '1') {
        // Проверяем и активируем биометрию
        let credId = localStorageGet("credId");

        if (credId) {
            // Проверяем сохраненные данные
            const res = await getBioKeyFromUser();
            if (res === false) {
                console.warn("Проверка регистрации биометрии не удалась, удаляем сохраненный credId");
                // Удалим сохраненные данные биометрии
                localStorageRemove('credId');
                localStorageRemove('salt');
                localStorageRemove('encData');
                sessionStorageRemove('bioKey');
                credId = false;
            }
        }

        if (!credId) {
            credId = await registerCredential();
            if (!credId) {
                // Не удалось активировать биометрию!
                console.log('Не удалось активировать биометрию! Фраза не будет сохранена!')
                alert('Не удалось активировать биометрию. Фраза не будет сохранена');
                checkboxSavePassphrase.checked = false;
                settingSavePassphrase = 0;
            }
        }
    } else {
        // пользователь снял галочку. Удалим сохраненную фразу, но оставим регистрацию биометрии
        localStorageRemove('encData'); // Удалим фразу из хранилища
    }
}

/**
 * Переключает глобальный флаг enableTools и записывает значение в localStorage
 * @returns void
 */
function updateSettingTools() {
    if (this instanceof HTMLElement) { // вызов через обработчик события
        const v = (this.checked) ? '1' : '0';
        if (!localStorageSet('enableTools', v)) {
            alert(messageStorageUnavailable);
        }
        enableTools = (v === '1'); // обновим глобальную переменную
    }
    // Дальше общий код и для event и для прямого вызова
    // обновим видимость элемента
    const btn = document.getElementById('btnTextArea');
    if (enableTools) {
        btn.classList.remove('hidden');
    } else {
        btn.classList.add('hidden');
    }
}

/**
 * Переключает глобальный флаг "отладка включена" и показывает / скрывает переключатель панели отладки
 * @returns {Promise<void>}
 */
async function updateSettingDebug() {
    const v = (this.checked) ? '1' : '0';
    if (!localStorageSet('enableDebug', v)) {
        alert(messageStorageUnavailable);
    }
    debugIsOn = (v === '1'); // обновим глобальную переменную
    if (debugIsOn) {
        updateElements([
            [['debugToggle'], 'classList', 'hidden', 'remove'],
        ]);
    } else {
        updateElements([
            [['debugToggle', 'debug'], 'classList', 'hidden', 'add'],
        ]);
    }
}

/**
 * Сворачивает / разворачивает панель отладки
 * @returns {Promise<void>}
 */
async function debugToggle() {
    const debug = document.getElementById('debug');
    const isHidden = debug.classList.contains('hidden');
    debug.classList.toggle('hidden', !isHidden);
    this.textContent = isHidden ? 'Отладка ▲' : 'Отладка ▼';
}

/**
 * Обновляет глобальную переменную unsafePassphrase и записывает настройку в localStorage
 * @returns {Promise<void>}
 */
async function updateSettingUnsafePassphrase() {
    const v = (this.checked) ? '1' : '0';
    if (!localStorageSet('unsafePassphrase', v)) {
        alert(messageStorageUnavailable);
    }
    unsafePassphrase = (v === '1'); // обновим глобальную переменную
}

/**
 * Показывает форму для шифрования / расшифровки произвольного текста с любой парольной фразой
 * @param e event
 */
function onBtnTextAreaClick(e) {
    e.preventDefault();
    const textPassphrase = document.getElementById('textPassphrase');
    if (textPassphrase.value === '') {
        textPassphrase.value = document.getElementById('passphrase').value;
        document.getElementById('textAreaIcons').textContent = document.getElementById('secretIcons').textContent;
        textAesKey = aesKey;
    }
    switchTo(['textArea']);
}


// ============================================================================================================
// ===================== Остальные общие и вспомогательные функции ============================================
// ===================== универсальные функции вынесены в main.js  ============================================

// === Help show ===
document.getElementById('btnHelpArea').onclick = (e) => {
    e.preventDefault();
    const lastArea= sessionStorageGet('lastSwitch');
    if(lastArea && lastArea !== 'helpArea'){
        sessionStorageSet('helpReturn',lastArea); // запомним куда возвращаться при закрытии справки
    }
    switchTo(['helpArea']);
}

// === Help Close button
document.getElementById('closeHelpBtn').onclick = (e) => {
    e.preventDefault();
    const lastArea = sessionStorageGet('helpReturn');
    if(lastArea && lastArea !== 'searchArea'){
        switchTo([lastArea]);
    }
    else{
        switchTo(['searchArea', 'loginInfo']);
    }
}

// === crypt / decrypt text показываем иконки при вводе passphrase ===
document.getElementById('textPassphrase').addEventListener('input', async function () {
    let icons = '';
    if (this.value) icons = sha256ToIcons(await sha256(this.value), 4);
    document.getElementById('textAreaIcons').textContent = icons; // выводим результат
});

document.getElementById('textPassphrase').addEventListener('change', async function () {
    [, , textAesKey] = await genKeys(this.value); // Получаем новый ключ для шифрования текста
    //console.log('New textAesKey from '+this.value);
});

// === Close crypt / decrypt text form ===
document.getElementById('closeTextBtn').onclick = (e) => {
    e.preventDefault();
    //document.getElementById('encodeTextArea').value = ''; // очистка формы
    switchTo(['searchArea', 'loginInfo']);
    document.getElementById('searchQuery').focus();
}

// === Crypt text ===
document.getElementById('doEncodeTextBtn').onclick = async (e) => {
    e.preventDefault();
    const area = document.getElementById('encodeTextArea');
    if (area.value === '') {
        return;
    }
    area.value = await encryptText(area.value, textAesKey);
}

// === Copy text btn ===
document.getElementById('copyTextBtn').onclick = async (e) => {
    e.preventDefault();
    const area = document.getElementById('encodeTextArea');
    await navigator.clipboard.writeText(area.value);
}

// === Paste text btn ===
document.getElementById('pasteTextBtn').onclick = async (e) => {
    e.preventDefault();
    const area = document.getElementById('encodeTextArea');
    area.value = await navigator.clipboard.readText();
}

// === Clear text btn ===
document.getElementById('clearTextBtn').onclick = (e) => {
    e.preventDefault();
    document.getElementById('encodeTextArea').value = '';
}

// === System settings ===
document.getElementById('lnkSettings').onclick = (e) => {
    e.preventDefault();
    if(document.getElementById('actionsArea').classList.contains('hidden')===false){
        updateElements(
            ['lnkSettings','textContent','Настройки ']
        );
        switchTo(['loginArea']);
    }
    else {
        updateElements(
            ['lnkSettings','textContent','Закрыть настройки']
        );
        switchTo(['loginArea', 'settingsArea', 'actionsArea']);
    }
}

// === Login Settings ===
document.getElementById('lnkLogout').onclick = (e) => {
    e.preventDefault();
    updateElements([[['searchResultsList'], 'textContent', '']]); // очистим результаты поиска
    switchTo("loginArea");
}


// === Passwd show form ===
document.getElementById('passwdBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    document.getElementById('passphrase1').value = document.getElementById('passphrase').value;
    document.getElementById('passphrase1').dispatchEvent(new Event('input', {bubbles: true}));
    switchTo("passwdArea");
}

// === Passwd Close button
document.getElementById('btnCancelPasswd').onclick = (e) => {
    e.preventDefault();
    updateElements([
        [['passphrase1', 'passphrase2'], 'value', ''],
        [['secretIcons4'], 'textContent', ''],
    ]);
    switchTo(['loginArea', 'settingsArea', 'actionsArea']);
}

// === Passwd process
document.getElementById('btnDoPasswd').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }

    const newPassphrase = document.getElementById('passphrase2').value;

    if (newPassphrase === '') {
        alert('Введите новую секретную фразу!');
        return false;
    }

    if (newPassphrase === document.getElementById('passphrase1').value) {
        alert('Новая фраза должна отличаться от старой!');
        return false;
    }

    if (!confirm('Важно: процедура изменение парольной фразы:\n\n1. Создаем аккаунт с новым ключом\n2. Получаем зашифрованные данные со старого аккаунта\n3. Расшифровуем полученные данные\n4. Шифруем данные с новым ключом\n5. Удаляем все существующие данные в НОВОМ аккаунте (если есть)\n6. Загружаем зашифрованные данные в новый аккаунт.\n7. Удаляем старый аккаунт со всеми данными\n\nРекомендуем сейчас прервать процесс и сохранить резервную копию, если вы этого не сделали ранее.\n\nЕсли резервная копия у вас уже есть - нажмите ОК, иначе Отмена')) {
        return;
    }

    // проверяем вход (и выполняем регистрацию если нужно) с новым логином
    const [newLogin, newSecretKey, newAesKey, newENC] = await genKeys(newPassphrase);
    if (debugIsOn) console.log(`Passwd from ${login} to ${newLogin} with key ${newSecretKey}`);

    let res = await sendRequest('login', {}, apiUrl, newLogin, newSecretKey);
    if (res && typeof res === 'object' && res.ok === true) {
        if (debugIsOn) console.log(`Вход выполнен на ${apiUrl} как ${newLogin}, записей в базе: ${res.records}`);
        if (res.records > 0) {
            if (!confirm(`Внимание: в аккаунте С НОВОЙ фразой сейчас уже есть ${res.records} записей\n\n Они будут УДАЛЕНЫ!\n\nХотите продолжить?`)) {
                return;
            }
        }
    } else if (res && typeof res === 'object' && res.error === 'user_not_registered') {
        if (res.signup === 1) {
            if (!await doSignup(apiUrl, newLogin, newSecretKey, {noConfirm: true})) {
                // Ошибка регистрации
                return false;
            }
        } else {
            // Пользователь не зарегистрирован, регистрация не разрешена
            alert("Не получается создать нового пользователя, т.к. сервер не разрешает новые регистрации");
            if (debugIsOn) console.warn(`Пользователь ${newLogin} с ключом ${newSecretKey} не существует на сервере ${apiUrl}. Регистрация не доступна.`);
            return false;
        }
    } else {
        showError("Login error", res);
        return false;
    }

    let totalCount, importedRecords;

    let btn = document.getElementById('btnDoPasswd');
    // Заблокируем кнопку на время обработки
    updateElements([
        [['btnDoPasswd', 'btnCancelPasswd'], 'disabled', true],
        ['btnDoPasswd', 'textContent', 'Обработка...'],
        ['btnDoPasswd', 'classList', 'actionBtn', 'remove']
    ]);

    // экспорт данных со старого логина
    /**
     * @typedef {Object} backupResponse
     * @property {string} filecontent
     * @property {boolean} ok
     * @property {string} filename
     * @property {number} count
     */

    /** @type {backupResponse} */
    res = await sendRequest('backup', {}, apiUrl, login, secretKey);
    if (res && typeof res === 'object' && res.ok === true) {
        const u8 = new Uint8Array([...atob(res.filecontent)].map(c => c.charCodeAt(0)));
        let text = await ungzip(u8);
        try {
            text = JSON.parse(text);
        } catch (e) {
            console.warn('Invalid JSON:', text.slice(0, 300) + '...');
            alert('Ошибка обработки, не валидный JSON в бекапе данных!');
            resetPasswdBtn();
            return;
        }

        totalCount = res.count; // Всего записей для переноса
        btn.textContent = `Обработка: 0 из ${totalCount}`;


        let i = 0;
        const data = []; // массив со всеми записями для загрузки на сервер через passwd
        for (const n of text.content) {
            i++;
            // Расшифровка полученных данных
            const title = await decryptText(n.rtitle, aesKey);
            const tags = await decryptText(n.rtags, aesKey);
            const text = await decryptText(n.content, aesKey);

            // Добавляем запись в новый логин
            // Кодируем данные и добавляем в список
            data.push({
                uid: n.uid,
                title: await newENC.encodeForIndex(title),
                rtitle: await encryptText(title, newAesKey),
                content: await encryptText(text, newAesKey),
                tags: await newENC.encodeForIndex(tags),
                rtags: await encryptText(tags, newAesKey),
                date_created: n.date_created,
                date_modified: n.date_modified
            });

            // обновим процент выполнения
            btn.textContent = `Обработка: ${i} из ${totalCount}`;
        }

        // Загрузка результатов на сервер
        btn.textContent = `Загрузка новых данных на сервер...`;
        const b64content = base64encode(JSON.stringify(data));
        res = await sendRequest('restore', {content: b64content, passwd: true}, apiUrl, newLogin, newSecretKey);
        if (res && typeof res === 'object' && res.ok === true) {
            importedRecords = res.rows;
        } else {
            showError('Не удалось загрузить новые данные на сервер\n\nВсе сделанные изменения отменены, ваша секретная фраза остается прежней!\n\nдетали ошибки: [op=restore]', res);
            resetPasswdBtn(); // разблокируем кнопки
            return false;
        }
        btn.textContent = `Обработка завершена`;

        // удаление старого логина и всех данных если все записи перенесены в новый
        res = await sendRequest('terminate', {}, apiUrl, login, secretKey);
        if (res && typeof res === 'object' && res.ok === true) {
            if (debugIsOn) console.warn(`Аккаунт ${login} удален`)
        } else {
            showError('Ошибка удаления старых данных:', res);
        }
        alert(`Секретная фраза изменена\n\nОбработано записей: ${importedRecords} из ${totalCount} шт.\n\nПрежний аккаунт и все его данные удалены. Сейчас будет выполнен вход с новой парольной фразой`);
        localStorageSet('dataChanged_' + newLogin.slice(-3), 'true'); // есть измененные данные для бекапа
        localStorageRemove('dataChanged_' + login.slice(-3));
        localStorageRemove('lastBackupDate_' + login.slice(-3));
        localStorageRemove('lastWarningDate_' + login.slice(-3));
        updateElements([
            [['passphrase1', 'passphrase2'], 'value', ''],
            [['secretIcons3', 'secretIcons4'], 'textContent', ''],
            [['passphrase'], 'value', newPassphrase], // обновим passphrase в интерфейсе
            ['progress2', 'style.width', '0%'],
        ]);
        resetPasswdBtn();
        document.getElementById('passphrase').dispatchEvent(new Event('input', {bubbles: true}));
        await doLogin(newPassphrase);

    } else {
        showError('Не удалось получить данные для расшифровки\n\nВаша секретная фраза остается прежней!\n\nдетали ошибки: [op=backup]', res);
        resetPasswdBtn(); // разблокируем кнопки
        return false;
    }
}

function resetPasswdBtn() {
    updateElements([
        [['btnDoPasswd', 'btnCancelPasswd'], 'disabled', false],
        ['btnDoPasswd', 'classList', 'actionBtn', 'add'],
        ['btnDoPasswd', 'textContent', 'Изменить секретную фразу'],
    ]);
}

// === Restore backup show form ===
document.getElementById('restoreBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    switchTo("restoreArea");
}
// === Restore backup Close button
document.getElementById('closeRestoreBtn').onclick = (e) => {
    e.preventDefault();
    // очистка данных
    updateElements([['fileInputBackup', 'value', '']]);
    cleanupRestore();
    switchTo(['loginArea', 'settingsArea', 'actionsArea']);
}

let restoreContent; //

// === Restore file load
document.getElementById('fileInputBackup').addEventListener('change', async (e) => {
    // очистка
    cleanupRestore();

    const file = e.target.files[0];
    if (!file) {
        return;
    }

    const info = document.getElementById('backupInfo');
    const name = file.name;
    const ext = name.split('.').pop().toLowerCase();

    let text;

    if (ext === 'gz') {
        // извлечем текст из архива
        try {
            const arrayBuffer = await file.arrayBuffer();
            text = await ungzip(arrayBuffer);
        } catch (err) {
            info.textContent = ('Ошибка: не удалось извлечь данных из GZIP архива. Вероятно, архив поврежден!');
            e.target.value = '';
            return false;
        }
    } else if (ext === 'json' || ext === 'txt') {
        // загружен текстовый JSON
        text = await file.text();
    } else {
        info.textContent = ('Ошибка: архив должен быть в формате xxxxx.json.gz (сжатый) или xxxxx.json (текстовый)');
        e.target.value = '';
        return false;
    }

    /** @type {{date?:string, rows?:number, signature?:string, content?:string}} */
    let data;

    try {
        data = JSON.parse(text);
    } catch (err) {
        info.textContent = ('Ошибка: не удалось разобрать данные JSON!');
        e.target.value = '';
        return false;
    }

    if (!data.date || !data.rows || !data.signature || !data.content || !Array.isArray(data.content) || data.content.length === 0) {
        info.textContent = ('Ошибка: Не удалось распознать структуру архива');
        e.target.value = '';
        return false;
    }

    // Проверка парольной фразы
    const recNum = rand(0, data.content.length - 1);
    const testText = await decryptText(data.content[recNum].rtitle, aesKey);
    if (testText === '[Corrupted data]' || testText === '[Corrupted data / invalid key]') {
        info.textContent = ('Ошибка: ваша текущая парольная фраза не подходит для этого бекапа!');
        e.target.value = '';
        return;
    }

    let sizeName = 'КБ';
    let sizeDivider = 1024;
    const contentLength = new TextEncoder().encode(text).length;
    if (contentLength > 1024 * 1024) {
        sizeName = 'МБ';
        sizeDivider = 1024 * 1024;
    }
    const contentSize = Math.round(contentLength / sizeDivider * 100) / 100;
    const serverMaxSize = Math.round(serverMaxInput / sizeDivider * 100) / 100;
    const checkSize = (contentSize < serverMaxSize) ? 'OK' : 'ERROR';


    info.textContent = `Файл: ${name}\nДата создания: ${data.date}\nЗаписей: ${data.content.length + 1} шт.\nРазмер: ${contentSize}${sizeName} (${checkSize}, сервер принимает до ${serverMaxSize}${sizeName})\nПодпись: ` + data.signature.slice(0, 6) + "..." + data.signature.slice(-6);
    restoreContent = data; // сохраним данные для последующей обработки
    updateElements([
        [['doRestoreBtn', 'doDecryptBtn'], 'disabled', false],
        ['doRestoreBtn', 'classList', 'actionBtn', 'add']
    ]);
});

// === Decrypt backup process
document.getElementById('doDecryptBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    if (!confirm('Экспорт данных\n\nВыбранный архив будет расшифрован и вы сможете сохранить все записи из него в JSON (текстовом) формате\n\nХотите продолжить?')) {
        return;
    }

    const data = [];
    for (const n of restoreContent.content) {
        data.push({
            id: n.uid,
            date_modified: n.date_modified,
            title: await decryptText(n.rtitle, aesKey),
            tags: await decryptText(n.rtags, aesKey),
            text: await decryptText(n.content, aesKey)
        });
    }
    document.getElementById('exportTextArea').value = JSON.stringify(data, null, 2); // заполним textarea
    exportCopied = false;

    // очистка
    cleanupRestore();
    switchTo('exportArea');
}

function cleanupRestore() {
    restoreContent = '';
    updateElements([
        [['doRestoreBtn', 'doDecryptBtn'], 'disabled', true],
        [['doRestoreBtn'], 'classList', 'actionBtn', 'remove'],
        ['backupInfo', 'textContent', 'файл бекапа не выбран'],
    ]);
}

// === Restore backup process
document.getElementById('doRestoreBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    if (restoreContent === '' || !restoreContent.signature || !Array.isArray(restoreContent.content || restoreContent.content.length === 0)) {
        alert('Сначала выберите файл бекапа для восстановления!');
        return;
    }

    if (!confirm('Восстановление бекапа\n\nВосстановление бекапа сначала УДАЛИТ все ваши текущие данные, а затем загрузит на сервер данные из архива\n\nХотите продолжить?')) {
        return;
    }

    const b64content = base64encode(JSON.stringify(restoreContent.content));
    const res = await sendRequest('restore', {
        content: b64content,
        backup_sign: restoreContent.signature
    }, apiUrl, login, secretKey);
    if (res && typeof res === 'object' && res.ok === true) {
        alert(`Восстановлено записей (${res.rows} шт.) выполнено`);
        document.getElementById('closeRestoreBtn').click();
    } else {
        showError('Восстановление бекапа', res);
    }
}

// === Import data show form ===
document.getElementById('importBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    switchTo("importArea");
}

// === Import file load
document.getElementById('fileInput').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    document.getElementById('importTextArea').value = await file.text();
});

// === Import data process
document.getElementById('doImportBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    const jsonStr = document.getElementById('importTextArea').value || '';
    if (jsonStr === '') {
        alert('Загрузите ваши данные JSON для импорта');
        return;
    }
    let arr = [];
    // Преобразуем строку в объект
    try {
        arr = JSON.parse(jsonStr);
    } catch (err) {
        console.error('json parse error:', err);
        alert('Не удалось разобрать данные JSON. Проверьте целостность и корректность данных.');
        return;
    }

    let importedRecords = 0;
    let errorRecords = 0;
    const totalRecords = arr.length;
    if (!confirm('Найдено записей: ' + totalRecords + 'шт. \n\nОни будут добавлены к вашим записям\n\nХотите продолжить?')) {
        return;
    }

    const results = document.getElementById('importLog');
    results.classList.remove('hidden');

    results.textContent = `Всего записей: ${totalRecords}\n\nНачинаем импорт:\n`;
    let i = 0;

    for (const item of arr) {
        i++;

        item.tags = item.tags.replace(/[\s,]+$/, ""); // trim для тегов, удалим лишнюю запятую в конце если есть

        // Кодируем данные
        const encTitle = await ENC.encodeForIndex(item.title);
        const encTags = await ENC.encodeForIndex(item.tags);
        const rEncText = await encryptText(item.text, aesKey);
        const rEncTitle = await encryptText(item.title, aesKey);
        const rEncTags = await encryptText(item.tags, aesKey);
        const operation = 'add';
        const id = '';

        // Отправляем запрос на сервер
        const res = await sendRequest(operation, {
                id,
                title: encTitle,
                tags: encTags,
                text: rEncText,
                rtitle: rEncTitle,
                rtags: rEncTags
            },
            apiUrl,
            login,
            secretKey);
        if (res.ok && res.id) {
            results.textContent = results.textContent + `${i}. ID: ${res.id} - ${item.title}\n`;
            importedRecords++;
        } else {
            results.textContent = results.textContent + `${i}. ERROR! - ${item.title}\n`;
            errorRecords++;
            showError("Импорт:", res);
        }
    }
    results.textContent = results.textContent + `Импорт завершен\n\nУспешно: ${importedRecords} из ${totalRecords}\nОшибок: ${errorRecords}\n\n`;
    localStorageSet('dataChanged_' + login.slice(-3), 'true'); // для предупреждения о бекапе
}

// === Import data Close button
document.getElementById('closeImportBtn').onclick = (e) => {
    e.preventDefault();
    updateElements([
        ['importTextArea', 'value', ''], // очистка формы
        ['importLog', 'textContent', ''],
        ['importLog', 'classList', 'hidden', 'add'],
    ]);
    switchTo(['loginArea', 'settingsArea', 'actionsArea']);
}

document.getElementById('pasteImportBtn')?.addEventListener('click', async () => {
    const textarea = document.getElementById('importTextArea');
    if (!textarea) return;
    try {
        textarea.value = await navigator.clipboard.readText();
    } catch (err) {
        console.error('Не удалось вставить из буфера обмена:', err);
    }
});

// Backup data
document.getElementById('backupBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    if (confirm('Резервное копирование\n\nВаши данные будут сохранены с сервера в зашифрованном виде, одним файлом.\n\nЭтот файл можно использовать как резервную копию для восстановления данных в будущем, а так же расшифровать и экспортировать как текст (JSON)\n\nХотите создать бекап?')) {
        /**
         * @typedef {Object} backupResponse
         * @property {string} filecontent
         * @property {boolean} ok
         * @property {string} filename
         */

        /** @type {backupResponse} */
        const res = await sendRequest('backup', {}, apiUrl, login, secretKey);
        if (res && typeof res === 'object' && res.ok === true) {

            // Проверка целостности данных в бекапе
            const u8 = new Uint8Array([...atob(res.filecontent)].map(c => c.charCodeAt(0)));
            let text = await ungzip(u8);
            try {
                text = JSON.parse(text);
            } catch (e) {
                console.warn('Invalid JSON:', text.slice(0, 300) + '...');
                alert('Ошибка обработки, не валидный JSON в бекапе данных!');
                resetPasswdBtn();
                return;
            }
            const backupCount = res.count; // Записей в бекапе по ответу сервера
            let okCount = 0;
            let errorCount = 0;
            for (const n of text.content) {
                // Расшифровка полученных данных
                const title = await decryptText(n.rtitle, aesKey);
                const tags = await decryptText(n.rtags, aesKey);
                const text = await decryptText(n.content, aesKey);
                const strings = [title, tags, text];
                const errors = ['[Corrupted data]', '[Corrupted data / invalid key]'];
                if (strings.some(s => errors.includes(s))) {
                    errorCount++; // Увеличиваем счетчик ошибок
                } else {
                    okCount++; // Увеличиваем счетчик ОК
                }
            }
            if (errorCount > 0) {
                alert(`Внимание!\n\nВ бекапе обнаружены поврежденные записи: ${errorCount} шт.`);
            }
            const backupCountReal = okCount + errorCount;
            if (backupCount !== backupCountReal) {
                alert(`внимание!\n\nОбнаружено несоответствие количества записей в бекапе!\n\nДолжно быть ${backupCount} шт, по факту ${backupCountReal} шт.`);
            }

            const uint8 = new Uint8Array([...atob(res.filecontent)].map(c => c.charCodeAt(0)));
            const blob = new Blob(
                [uint8],
                {type: "application/gzip"}
            );

            // создаём временную ссылку на этот blob
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = res.filename;

            // "нажимаем" ссылку программно для инициации сохранения файла браузером
            document.body.appendChild(a);
            a.click();

            // очищаем за собой
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Записываем дату создания последнего бекапа в localStorage
            const now = new Date().toISOString();
            const suffix = login.slice(-3);
            localStorageSet('lastBackupDate_' + suffix, now);
            localStorageSet('lastWarningDate_' + suffix, now);
            localStorageRemove('dataChanged_' + suffix);
            if (debugIsOn) console.log('Дата последнего бэкапа сохранена в localStorage:', now);
        } else {
            showError('Backup', res);
        }
    }
}

let exportCopied = false; // флаг, что пользователь скопировал данные экспорта

// === Export data ===
document.getElementById('exportBtn').onclick = async (e) => {
    e.preventDefault();
    if (!isLoggedIn || !login) {
        alert(messagePleaseLoginFirst);
        return;
    }
    if (confirm('Экспорт данных\n\nВсе ваши заметки будут загружены с сервера, расшифрованы и сохранены в JSON (текстовом) формате\n\nЕсли вы хотите создать безопасную резервную копию данных - вместо "экспорта" нажмите "Скачать бекап" .\n\nХотите продолжить экспорт?')) {
        const out = document.getElementById('exportTextArea');
        if (!out) {
            alert('Ошибка - не могу найти exportTextArea для вывода результатов');
            return;
        }

        /**
         * @typedef {Object} exportResponse
         * @property {{title: string, text: string, tags: string, date_modified: string}} results
         * @property {boolean} ok
         * @property {number} count
         */

        /** @type {exportResponse} */
        const res = await sendRequest('export', {}, apiUrl, login, secretKey);
        if (res && typeof res === 'object' && res.ok === true) {
            if (!res.results || !res.results.length || !res.count) {
                alert('Ни одной записи для экспорта не найдено');
                return;
            }
            const data = [];
            for (const n of res.results) {
                data.push({
                    id: n.id,
                    date_modified: n.date_modified,
                    title: await decryptText(n.title, aesKey),
                    tags: await decryptText(n.tags, aesKey),
                    text: await decryptText(n.text, aesKey)
                });
            }
            out.value = JSON.stringify(data, null, 2); // заполним textarea
            exportCopied = false;
        } else {
            showError('Экспорт данных', res);
        }
        switchTo("exportArea");
    }
}

// === Export data Close button
document.getElementById('closeExportBtn').onclick = (e) => {
    e.preventDefault();
    if (exportCopied || confirm('Вы скопировали / сохранили данные?')) {
        document.getElementById('exportTextArea').value = ''; // очистка формы
        switchTo(['loginArea', 'settingsArea', 'actionsArea']);
    }
}

// === Export data Copy button
document.getElementById('copyExportBtn')?.addEventListener('click', () => {
    const txt = document.getElementById('exportTextArea')?.value || '';
    const res = navigator.clipboard.writeText(txt);
    if(res) {
        alert('Скопировано\n\nСохраните данные (например в TXT файл) для дальнейшего использования');
    }
    exportCopied = true;
});

// Export data Save button
document.getElementById('saveExportBtn').addEventListener('click', () => {
    const text = document.getElementById('exportTextArea').value || '';
    const filename = 'export_data.txt';

    // создаём Blob (объект файла)
    const blob = new Blob([text], {type: 'text/plain;charset=utf-8'});

    // создаём временную ссылку на этот blob
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;

    // «нажимаем» ссылку программно
    document.body.appendChild(a);
    a.click();
    exportCopied = true;

    // очищаем за собой
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});

// === Логин ===
document.getElementById('loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    let passphrase = document.getElementById('passphrase').value;
    if (!passphrase) {
        alert('Секретная фраза не найдена!');
        return;
    }
    await doLogin(passphrase);
});

// === Поиск ===
document.getElementById('searchForm').addEventListener('submit', async e => {
    e.preventDefault();

    const query = document.getElementById('searchQuery').value.replace(/[\s,]+$/, ""); // Удалим запятую в конце
    if (!query) return;

    if (/#\d{1,5}/i.test(query)) {
        // Пользователь ввел идентификатор записи, откроем сразу заметку
        document.getElementById('searchQuery').value = '';
        await viewNote(query.slice(1));
        return;
    }

    document.getElementById('searchQuery').blur();

    const normalizedQuery = String(query).toLowerCase();
    const allWords = ['все', 'всё', 'all', 'dct'];
    const encQuery = (allWords.includes(normalizedQuery)) ? "ALL" : await ENC.encodeForIndex(query);
    const res = await sendRequest('search', {query: encQuery}, apiUrl, login, secretKey);
    if (res && typeof res === 'object' && res.ok === true) {
        await showResults(res);
    } else {
        showError('search', res);
    }
});


async function doLogin(passphrase, doNotSave = false) {
    // Проверка комплексности парольной фразы
    let minScore = 80;
    if (!unsafePassphrase && scorePassphrase < 80) {
        switchTo(['loginArea', 'settingsArea']);
        alert(`Сложность пароля слишком низкая - ${scorePassphrase}%, должно быть минимум ${minScore}%!\n\nЕсли вы хотите использовать слабые небезопасные пароли - отключите проверку в настройках\n\nРекомендации:\n- длинна - 15 и более символов\n- наличие букв разного регистра\n- наличие цифр\n- наличие спецсимволов (/.?!:&;#@*> и т.д.)\n- не менее 5 уникальных (разных) букв`);
        return false;
    }

    apiUrl = selectApiServer.value;

    // Покажем название сервера
    const serverName = document.getElementById('server-name');
    serverName.textContent = selectApiServer.selectedOptions[0].text;
    const serverType = selectApiServer.options[selectApiServer.selectedIndex].getAttribute('data-type');
    if (serverType !== 'master') {
        serverName.classList.add('slave-server');
    } else {
        serverName.classList.remove('slave-server');
    }

    [login, secretKey, aesKey, ENC] = await genKeys(passphrase); // установка глобальных переменных

    // Отладка
    if (debugIsOn) {
        const debug = document.getElementById('debug');
        debug.textContent = '';
        debug.textContent += `Login: ${login}\nSecret_key: ${secretKey}\n`;
    }

    // логин
    /**
     * @typedef {Object} LoginResponse
     * @property {boolean} ok
     * @property {number} records
     * @property {string} error
     * @property {number} signup
     * @property {string} v
     * @property {string} welcome_message
     * @property {number} max_input
     */

    /** @type {LoginResponse} */
    const res = await sendRequest('login', {}, apiUrl, login, secretKey);

    if (res && typeof res === 'object' && res.ok === true && res.v !== required_api_version) {
        alert(`Внимание: версия API (${res.v}) отличается от рекомендуемой (${required_api_version})!\n\nВозможны ошибки в работе`);
    }

    const lastServerUsed = sessionStorageGet('lastServerUsed');
    if (res.welcome_message && lastServerUsed !== apiUrl) {
        alert(res.welcome_message);
    }
    sessionStorageSet('lastServerUsed', apiUrl);

    if (res && typeof res === 'object' && res.ok === true) {
        if (debugIsOn) console.log(`Вход выполнен на ${apiUrl} как ${login}, записей в базе: ${res.records}`);

    } else if (res && typeof res === 'object' && res.error === 'user_not_registered') {
        if (res.signup === 1) {
            if (!await doSignup(apiUrl, login, secretKey)) {
                switchTo(['loginArea', 'settingsArea']);
                return false;
            }
        } else {
            // Пользователь не зарегистрирован, регистрация не разрешена
            alert(`Такой пользователь не зарегистрирован на сервере и сервер не разрешает новые регистрации\n\nДля регистрации сообщите администратору ваши\n- ID: ${login}\n- SecretKey: ${secretKey}\n\n(можно скопировать из данных отладки)`);
            if (debugIsOn) console.warn(`Пользователь ${login} с ключом ${secretKey} не существует на сервере ${apiUrl}. Регистрация не доступна.`);
            switchTo(['loginArea', 'settingsArea']);
            return false;
        }

    } else {
        showError("Login error", res);
        switchTo(['loginArea', 'settingsArea']);
        return false;
    }

    // Обновим максимальный размер запроса, если север его сообщает
    if (res.max_input) {
        serverMaxInput = res.max_input;
    }

    isLoggedIn = true; // установим флаг успешного логина

    // Сохраним введенную секретную фразу
    sessionStorageSet('passphrase', passphrase); // для сессии
    if (settingSavePassphrase === '1' && !doNotSave) {
        sessionStorageSet('passphrase', passphrase); // сохраняем в сессию
        let bioKey;
        try {
            console.log('doLogin: Шифруем и сохраняем passphrase в localStorage');
            bioKey = await getBioKey();

        } catch (e) {
            console.error('doLogin -> getBioKey: ' + e);
            console.error('doLogin: не удалось получить bioKey и зашифровать фразу для localStorage!')
        }

        if (bioKey) {
            const aesKey = await crypto.subtle.importKey("raw", bioKey, "AES-GCM", false, ["encrypt", "decrypt"]);
            let encryptedPassphrase = await encryptText(passphrase, aesKey);
            localStorageSet('encData', encryptedPassphrase);
            console.log('doLogin: записали зашифрованную фразу в encData в localStorage');
        }
    }

    // проверим и покажем предложение создать бекап, если есть данные
    if (res.records > 0) {
        await checkBackupDate();
    }

    // Изменения в интерфейсе после инициализации и логина
    updateElements([
        [['passwdBtn', 'exportBtn', 'backupBtn', 'restoreBtn', 'importBtn', 'terminateAccountBtn'], 'disabled', false],
        ['btnLogout', 'classList', 'hidden', 'remove'],
        ['searchQuery', 'value', ''] // очистка поля поиска
    ]);

    let lastSwitch = sessionStorageGet('lastSwitch');
    let lastViewID = sessionStorageGet('lastViewID');
    let lastEditID = sessionStorageGet('lastEditID');

    switchTo(['searchArea', 'loginInfo']);
    document.getElementById('searchQuery').focus();

    // Восстановим последнее действие, если оно было
    if (lastSwitch === 'viewArea' && lastViewID) {
        // откроем заново просмотр заметки
        await viewNote(lastViewID);
    } else if (lastSwitch === 'editArea' && lastEditID) {
        // откроем заново форму редактирования
        await viewNote(lastEditID);
        document.getElementById('btnActionEdit').click();
    }
}

async function showResults(res) {
    const container = document.getElementById('searchResultsList');
    container.classList.remove('hidden'); // покажем область результатов поиска
    container.innerHTML = '';

    if (!res || typeof res !== 'object' || !res.results || !res.results.length) {
        const empty = document.createElement('i');
        empty.textContent = 'Ничего не найдено';
        container.appendChild(empty);
        return;
    }

    // есть результаты поиска
    container.innerHTML = "<div class='align-right'><a href='#' id='clearResultLink'>Очистить результаты <svg width=\"16\" height=\"16\" viewBox=\"0 0 16 16\" fill=\"currentColor\"><path d=\"M2.344 2.343h-.001a8 8 0 0 1 11.314 11.314A8.002 8.002 0 0 1 .234 10.089a8 8 0 0 1 2.11-7.746Zm1.06 10.253a6.5 6.5 0 1 0 9.108-9.275 6.5 6.5 0 0 0-9.108 9.275ZM6.03 4.97 8 6.94l1.97-1.97a.749.749 0 0 1 1.275.326.749.749 0 0 1-.215.734L9.06 8l1.97 1.97a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L8 9.06l-1.97 1.97a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734L6.94 8 4.97 6.03a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018Z\"></path></svg></a></div>";
    const clearResultLink = document.getElementById('clearResultLink');
    if (clearResultLink) {
        clearResultLink.addEventListener('click', (event) => {
            event.preventDefault();
            document.getElementById('searchQuery').value = '';
            document.getElementById('searchQuery').focus();
            container.innerHTML = '';
            container.classList.add('hidden');
        });
    }

    for (const n of res.results) {
        const div = document.createElement('div');
        div.className = 'note';
        div.id = `note${n.id}`;
        const title = await decryptText(n.title, aesKey);
        const linkOpen = document.createElement('a');
        linkOpen.href = '#';
        linkOpen.className = 'action-link';
        linkOpen.textContent = title;
        linkOpen.addEventListener('click', (e) => {
            e.preventDefault();
            viewNote(n.id);
        });
        div.append(linkOpen);
        container.appendChild(div);
    }
}

// === Добавление ===
document.getElementById('btnNew').onclick = () => {
    updateElements([
        [['editId', 'editTitleInput', 'editTagsInput', 'editTextInput'], 'value', ''],
        ['editTextInput', 'defaultValue', ''],
        ['editTitle', 'textContent', 'Новая запись']
    ]);
    makeWysiwyg('editTextInput');
    switchTo('editArea');
    document.getElementById('editTitleInput').focus();
};

// ==== Нажата кнопка Отмена на странице редактирования
document.getElementById('btnCancelEdit').onclick = () => {
    document.getElementById('editForm').reset(); // отмена изменений в текст
    const id = document.getElementById('editId').value;
    if (id) {
        sessionStorageRemove('lastEditID');
        switchTo('viewArea');
        sessionStorageSet('lastViewID', id);
    } else {
        switchTo(['searchArea', 'loginInfo']);
        if (!document.getElementById('searchQuery').value) {
            document.getElementById('searchQuery').focus();
        }
    }
};

// Обработка отправка формы добавления / редактирования записи
document.getElementById('editForm').onsubmit = async e => {
    e.preventDefault();
    if (debugIsOn) console.log('submit form to server');
    const id = document.getElementById('editId').value;
    const title = document.getElementById('editTitleInput').value;
    let tags = document.getElementById('editTagsInput').value;
    const text = document.getElementById('editTextInput').value;

    tags = tags.replace(/[\s,]+$/, ""); // trim для тегов, удалим лишнюю запятую в конце если есть

    // Проверка, заполнены ли все поля
    if (!title || !tags || !text) {
        alert('Все поля должны быть заполнены!');
        return;
    }

    // Кодируем данные
    const encTitle = await ENC.encodeForIndex(title);
    const encTags = await ENC.encodeForIndex(expandTags(tags));
    const rEncText = await encryptText(text, aesKey);
    const rEncTitle = await encryptText(title, aesKey);
    const rEncTags = await encryptText(tags, aesKey);
    const operation = id ? 'modify' : 'add';

    // Отправляем запрос на сервер
    const res = await sendRequest(operation, {
            id,
            title: encTitle,
            tags: encTags,
            text: rEncText,
            rtitle: rEncTitle,
            rtags: rEncTags
        },
        apiUrl,
        login,
        secretKey);
    if (res && typeof res === 'object' && res.ok === true && res.id) {
        localStorageSet('dataChanged_' + login.slice(-3), 'true'); // для предупреждения о бекапе
        // Изменения в форму добавления
        sessionStorageRemove('lastEditID');
        await viewNote(res.id);
        return;
    }
    showError(operation, res);
};

// === Удаление ===
async function deleteNote(id) {
    if (!confirm("Удалить запись " + id + "?")) return;
    const res = await sendRequest('delete', {id}, apiUrl, login, secretKey);
    if (res && typeof res === 'object' && res.ok === true) {
        switchTo(['searchArea', 'loginInfo']);
        if (document.getElementById('searchQuery').value) {
            await document.getElementById('searchBtn').click();
        } else {
            document.getElementById('searchQuery').focus();
        }
        sessionStorageRemove('lastViewID'); // "Забудем" ID
    } else {
        showError('delete', res);
    }
}


// === Просмотр и форма редактирования ===
async function viewNote(id) {

    /**
     * @typedef {Object} GetResponse
     * @property {{title: string, text: string, tags: string, date_modified: string}} note
     */

    /** @type {GetResponse} */
    const res = await sendRequest('get', {id}, apiUrl, login, secretKey);
    if (res && typeof res === 'object' && res.note && typeof res.note === 'object') {

        let noteDate = (res.note.date_modified) ? formatDate(res.note.date_modified, 'd.m.y H:i') : '';
        let noteContent = (res.note.content) ? await decryptText(res.note.content, aesKey) : '';
        let noteTitle = (res.note.rtitle) ? await decryptText(res.note.rtitle, aesKey) : '';
        let noteTags = (res.note.rtags) ? await decryptText(res.note.rtags, aesKey) : '';

        // Обработка текста
        let noteContentView = bbcodeToHtml(noteContent);

        // Заполняем форму редактирования
        document.getElementById('editTitle').textContent = `Редактирование записи ${id}`;
        document.getElementById('editId').defaultValue = id;
        document.getElementById('editTitleInput').defaultValue = noteTitle;
        document.getElementById('editTagsInput').defaultValue = noteTags;
        document.getElementById('editTextInput').defaultValue = noteContent;
        document.getElementById('editId').value = id;
        document.getElementById('editTitleInput').value = noteTitle;
        document.getElementById('editTagsInput').value = noteTags;
        document.getElementById('editTextInput').value = noteContent;

        // Заполняем форму просмотра
        document.getElementById('viewTitle').textContent = noteTitle;
        document.getElementById('viewContent').innerHTML = noteContentView;
        document.getElementById('viewDate').textContent = noteDate + ', ID #' + id;
        document.getElementById('viewTags').innerHTML = formatTags(noteTags, 'tag-label');

        // Кнопка закрытия
        document.getElementById('btnActionClose').onclick = () => {
            // очистим форму просмотра и редактирования
            updateElements([
                [['editId', 'editTitleInput', 'editTagsInput', 'editTextInput'], 'value', ''],
                [['editId', 'editTitleInput', 'editTagsInput', 'editTextInput'], 'defaultValue', ''],
                [['editTitle', 'viewTitle', 'viewContent', 'viewTags'], 'textContent', '']
            ]);
            // обновляем результаты поиска
            switchTo(['searchArea', 'loginInfo']);
            if (document.getElementById('searchQuery').value) {
                document.getElementById('searchBtn').click();
            } else {
                document.getElementById('searchQuery').focus();
            }
            sessionStorageRemove('lastViewID'); // "Забудем" ID
        }

        // Кнопка редактирования
        document.getElementById('btnActionEdit').onclick = () => {
            makeWysiwyg('editTextInput');
            switchTo('editArea');
            document.getElementById('editTitleInput').focus();
            sessionStorageRemove('lastViewID'); // "Забудем" ID
            sessionStorageSet('lastEditID', id);
        }

        // Кнопка удаления
        document.getElementById('btnActionDelete').onclick = () => deleteNote(id);

        // Активируем обработчик внутренних ссылок
        initInternalLinks();
        // Показываем форму просмотра
        switchTo('viewArea');

        // Сохраним id заметки на случай перезагрузки страницы
        sessionStorageSet('lastViewID', id);

    } else {
        showError('get', res);
    }

}

function switchTo(activeIds) {
    if (debugIsOn) console.log('switchTo ' + activeIds);
    // Список всех id, с которыми работает функция
    const ids = ["viewArea", "searchArea", "editArea", "loginArea", "helpArea", "actionsArea", "settingsArea", "exportArea", "importArea", "loginInfo", "passwdArea", "textArea", "restoreArea"];

    // Преобразуем параметр в массив, если это не массив
    const activeList = Array.isArray(activeIds) ? activeIds : [activeIds];

    // Пройтись по списку и скрыть все элементы
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            // Если этот id присутствует в списке активных — показываем, иначе скрываем
            if (activeList.includes(id)) {
                el.classList.remove('hidden');
            } else {
                el.classList.add('hidden');
            }
        }
    });

    activeArea = activeList[0] || ''; // установим флаг какая область сейчас активна

    // Запомнить последние активные области
    sessionStorageSet('lastSwitch', activeList[0] || '');
}

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
    return await crypto.subtle.deriveKey(
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

    // Разбиваем на части
    for (let offset = 0; offset < textBytes.length; offset += CHUNK_SIZE) {
        const part = textBytes.subarray(offset, offset + CHUNK_SIZE);
        const iv = await crypto.getRandomValues(new Uint8Array(IV_SIZE));
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
    //let mySign = await sha256(base);
    //if (debugIsOn === true) document.getElementById('debug').textContent += "\nmakeSignature => " + base + " " + mySign + "\n";
    return sha256(base);
}

// === AJAX ===
async function sendRequest(operation, data, apiUrl, login, mySecretKey = '') {
    if (debugIsOn) console.log(`sendRequest('${operation}',...)`);
    const timestamp = Math.floor(Date.now() / 1000);
    const sign = await makeSignature(operation, timestamp, data, login, mySecretKey);
    const payload = {login, timestamp, operation, sign, ...(data || {})};

    if (isPayloadTooLarge(payload, serverMaxInput)) {
        const sizeMB = (new TextEncoder().encode(JSON.stringify(payload)).length / (1024 * 1024)).toFixed(2);
        const msg = `Размер данных для отправки на сервер слишком большой (~${sizeMB} МБ)\n\n` +
            `Сервер принимает не более ${serverMaxInput / (1024*1024)} МБ.`;
        return { ok: false, error: "payload_too_large_locally", msg: msg };
    }

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
        /(?<!\[url=)(?<!\[link=)(https?:\/\/[^\s<>\]\[]*?)([.,)]?)(?=$|\s|<|>|,|\)|])/gi,
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
        {re: /\[h3](.*?)\[\/h3]/gis, to: "<h3>$1</h3>"},
        {re: /\[h4](.*?)\[\/h4]/gis, to: "<h4>$1</h4>"},
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
        {re: /\[justify](.*?)\[\/justify]/gis, to: "<div class='align-justify'>$1</div>"},
        {re: /\[center](.*?)\[\/center]/gis, to: "<div class='align-center'>$1</div>"},
        {
            re: /\[url=#([0-9]+)](.*?)\[\/url]/gis,
            to: '<a href="#$1" data-id="$1" class="internal-link">$2</a>'
        },
        {
            re: /\[url=https:\/\/(www\.dropbox\.com|1drv\.ms|drive\.google\.com|cloud\.mail\.ru)([^\]#]+)](.*?)\[\/url]/gis,
            to: '<a href="https://$1$2" class="link-with-icon" target="_blank" rel="noopener noreferrer">$3</a>'
        },
        {
            re: /\[url=([^\]#]+)](.*?)\[\/url]/gis,
            to: '<a href="$1" target="_blank" rel="noopener noreferrer">$2</a>'
        },
        {
            re: /\[link=([^\]]+)](.*?)\[\/link]/gis,
            to: '<a href="$1" target="_blank" rel="noopener noreferrer">$2</a>'
        },

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
    suggestionBox.id = 'autocomplete-' + inputId;
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

    // Убираем подсказки при отправке формы
    inputElem.form?.addEventListener('submit', () => {
        suggestionBox.style.display = 'none';
        suggestionBox.innerHTML = '';
    });
}

/**
 * Прокручивает список, чтобы активный элемент был видимым
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
        {label: '<em>i</em>', tag: 'i'},
        {label: '<u>U</u>', tag: 'u'},
        {label: '<s>S</s>', tag: 's'},
        {label: '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" class="rotate90">\n' +
                '  <path d="M10.896 2H8.75V.75a.75.75 0 0 0-1.5 0V2H5.104a.25.25 0 0 0-.177.427l2.896 2.896a.25.25 0 0 0 .354 0l2.896-2.896A.25.25 0 0 0 10.896 2ZM8.75 15.25a.75.75 0 0 1-1.5 0V14H5.104a.25.25 0 0 1-.177-.427l2.896-2.896a.25.25 0 0 1 .354 0l2.896 2.896a.25.25 0 0 1-.177.427H8.75v1.25Zm-6.5-6.5a.75.75 0 0 0 0-1.5h-.5a.75.75 0 0 0 0 1.5h.5ZM6 8a.75.75 0 0 1-.75.75h-.5a.75.75 0 0 1 0-1.5h.5A.75.75 0 0 1 6 8Zm2.25.75a.75.75 0 0 0 0-1.5h-.5a.75.75 0 0 0 0 1.5h.5ZM12 8a.75.75 0 0 1-.75.75h-.5a.75.75 0 0 1 0-1.5h.5A.75.75 0 0 1 12 8Zm2.25.75a.75.75 0 0 0 0-1.5h-.5a.75.75 0 0 0 0 1.5h.5Z"></path>\n' +
                '</svg>', tag: 'center'},
        {label: '<svg aria-hidden="true" height="16" viewBox="0 0 16 16" width="16" data-view-component="true" class="octicon octicon-list-ordered">\n' +
                '    <path d="M5 3.25a.75.75 0 0 1 .75-.75h8.5a.75.75 0 0 1 0 1.5h-8.5A.75.75 0 0 1 5 3.25Zm0 5a.75.75 0 0 1 .75-.75h8.5a.75.75 0 0 1 0 1.5h-8.5A.75.75 0 0 1 5 8.25Zm0 5a.75.75 0 0 1 .75-.75h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1-.75-.75ZM.924 10.32a.5.5 0 0 1-.851-.525l.001-.001.001-.002.002-.004.007-.011c.097-.144.215-.273.348-.384.228-.19.588-.392 1.068-.392.468 0 .858.181 1.126.484.259.294.377.673.377 1.038 0 .987-.686 1.495-1.156 1.845l-.047.035c-.303.225-.522.4-.654.597h1.357a.5.5 0 0 1 0 1H.5a.5.5 0 0 1-.5-.5c0-1.005.692-1.52 1.167-1.875l.035-.025c.531-.396.8-.625.8-1.078a.57.57 0 0 0-.128-.376C1.806 10.068 1.695 10 1.5 10a.658.658 0 0 0-.429.163.835.835 0 0 0-.144.153ZM2.003 2.5V6h.503a.5.5 0 0 1 0 1H.5a.5.5 0 0 1 0-1h.503V3.308l-.28.14a.5.5 0 0 1-.446-.895l1.003-.5a.5.5 0 0 1 .723.447Z"></path>\n' +
                '</svg>', tag: 'olblock'},
        {label: '<svg aria-hidden="true" height="16" viewBox="0 0 16 16" width="16" data-view-component="true" class="octicon octicon-list-unordered">\n' +
                '    <path d="M5.75 2.5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5Zm0 5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5Zm0 5h8.5a.75.75 0 0 1 0 1.5h-8.5a.75.75 0 0 1 0-1.5ZM2 14a1 1 0 1 1 0-2 1 1 0 0 1 0 2Zm1-6a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM2 4a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z"></path>\n' +
                '</svg>', tag: 'ulblock'},
        {label: '<svg aria-hidden="true" height="16" viewBox="0 0 16 16" width="16" data-view-component="true" class="octicon octicon-link">\n' +
                '    <path d="m7.775 3.275 1.25-1.25a3.5 3.5 0 1 1 4.95 4.95l-2.5 2.5a3.5 3.5 0 0 1-4.95 0 .751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018 1.998 1.998 0 0 0 2.83 0l2.5-2.5a2.002 2.002 0 0 0-2.83-2.83l-1.25 1.25a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042Zm-4.69 9.64a1.998 1.998 0 0 0 2.83 0l1.25-1.25a.751.751 0 0 1 1.042.018.751.751 0 0 1 .018 1.042l-1.25 1.25a3.5 3.5 0 1 1-4.95-4.95l2.5-2.5a3.5 3.5 0 0 1 4.95 0 .751.751 0 0 1-.018 1.042.751.751 0 0 1-1.042.018 1.998 1.998 0 0 0-2.83 0l-2.5 2.5a1.998 1.998 0 0 0 0 2.83Z"></path>\n' +
                '</svg>', tag: 'url'},
        {label: '―', tag: 'hr', single: 'true'},
        {label: '#', tag: 'code'},
        {label: '❏️', tag: 'quote'},
        {label: 'H3', tag: 'h3'},
        {label: 'H4', tag: 'h4'},
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
                textarea.value = bbFromHtml(html);
                editable.classList.add('hidden');
                textarea.classList.remove('hidden');
                btn.textContent = '✨';
                textarea.focus();
            } else {
                // === обратно в визуальный ===
                const bbText = textarea.value.replace(/\r\n?/g, '\n');
                editable.innerHTML = bbToHtml(bbText);
                textarea.classList.add('hidden');
                editable.classList.remove('hidden');
                btn.textContent = '⌘';
                editable.focus();
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
        // execCommand устарел, но все еще работает с contentEditable
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
            .replace(/\[justify](.*?)\[\/justify]/gis, '<div class="align-justify">$1</div>')
            .replace(/\[center](.*?)\[\/center]/gis, '<div class="align-center">$1</div>')
            .replace(/\[quote](.*?)\[\/quote]/gis, '<pre>$1</pre>')
            .replace(/\[code](.*?)\[\/code]/gis, '<code>$1</code>')
            .replace(/\n*\[ol]\n*/gi, '<ol>').replace(/\n*\[\/ol]\n*/gi, '</ol>')
            .replace(/\n*\[ul]\n*/gi, '<ul>').replace(/\n*\[\/ul]\n*/gi, '</ul>')
            .replace(/\[li]/gi, '<li>').replace(/\[\/li]\n?/gi, '</li>')
            .replace(/\[h3]/gi, '<h3>').replace(/\[\/h3]\n?/gi, '</h3>')
            .replace(/\[h4]/gi, '<h4>').replace(/\[\/h4]\n?/gi, '</h4>')
            .replace(/\[b]/gi, '<b>').replace(/\[\/b]/gi, '</b>')
            .replace(/\[i]/gi, '<i>').replace(/\[\/i]/gi, '</i>')
            .replace(/\[u]/gi, '<u>').replace(/\[\/u]/gi, '</u>')
            .replace(/\[s]/gi, '<s>').replace(/\[\/s]/gi, '</s>')
            .replace(/\s*\[hr]\s*\n?/gi, '<hr>')
            .replace(/\n/g, '<br>');
    }


    function bbFromHtml(html) {
        //alert('debug: '+html);
        let out = html
            .replace(/<div class="align-center">(.*?)<\/div>/gis, '[center]$1[/center]')
            .replace(/<center>(.*?)<\/center>/gis, '[center]$1[/center]')
            .replace(/<div class="align-justify">(.*?)<\/div>/gis, '[justify]$1[/justify]')
            .replace(/\r\n?/g, '\n')
            .replace(/<div>/gi, '\n')
            .replace(/<\/div>/gi, '')
            .replace(/<hr[^>]*>\s*(?:<br\s*\/?>|\n|\r\n?)+/gi, '<hr>')
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<div><br><\/div>/gi, '\n')
            .replace(/<ol>/gi, '\n[ol]\n').replace(/<\/ol>/gi, '[/ol]\n\n')
            .replace(/<ul>/gi, '\n[ul]\n').replace(/<\/ul>/gi, '[/ul]\n\n')
            .replace(/<li>/gi, '[li]').replace(/<\/li>/gi, '[/li]\n')
            .replace(/<b>/gi, '[b]').replace(/<\/b>/gi, '[/b]')
            .replace(/<h3>/gi, '[h3]').replace(/<\/h3>/gi, '[/h3]\n')
            .replace(/<h4>/gi, '[h4]').replace(/<\/h4>/gi, '[/h4]\n')
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
            .replace(/\n?\[ul]\n*/gi, '[ul]').replace(/\n*\[\/ul]\n?/gi, '[/ul]')
            .replace(/\[h4]/gi, '[h4]').replace(/\[\/h4]\n*/gi, '[/h4]')
            .replace(/\[h3]/gi, '[h3]').replace(/\[\/h3]\n*/gi, '[/h3]');
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
            // noinspection JSUnresolvedReference
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
    // Компактная JS-реализация inflate.
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

/**
 * Проверка даты последнего бэкапа
 */
async function checkBackupDate() {
    // Проверка при входе: нужно ли предупреждать о бэкапе
    const X = 14; // Порог в днях (для бэкапа и предупреждений)
    const suffix = login.slice(-3);
    const dataChanged = localStorageGet('dataChanged_' + suffix);
    if (!dataChanged) {
        return;
    }
    /** @type {string} */
    const lastBackupDateStr = localStorageGet('lastBackupDate_' + suffix);
    /** @type {string} */
    const lastWarningDateStr = localStorageGet('lastWarningDate_' + suffix);
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

        const message = (daysSinceBackup === false) ? `Похоже вы еще не создавали бекап данных для этого аккаунта. Хотите создать?` : `Вы создавали последний бекап данных ${daysSinceBackup} дн. назад. Хотите создать новый?`;
        if (confirm(message)) {
            // Инициируем создание бекапа
            switchTo(['loginArea', 'settingsArea', 'actionsArea']);
            document.getElementById('backupBtn').click();
        } else {
            // Пользователь отказался от бекапа, просто фиксируем дату предупреждение
            localStorageSet('lastWarningDate_' + suffix, now.toISOString());
        }
    }
}

function evaluatePassphrase(inputId, progressId) {
    const passphraseInput = document.getElementById(inputId);
    const progressBar = document.getElementById(progressId);

    const MAX_LENGTH_BASE = 50;      // за первые 15 символов
    const BONUS_PER_CHAR = 1;        // +1% за каждый символ сверх 15
    const MAX_LENGTH_TOTAL = 65;     // абсолютный потолок за длину

    const MAX_CASES = 10;
    const MAX_DIGITS = 10;
    const MAX_SPECIAL = 10;
    const BONUS_ALL = 10;

    const phrase = passphraseInput.value;
    let score = 0;

    // 1. Длина
    const length = phrase.length;
    let lengthScore;

    if (length <= 15) {
        lengthScore = (length / 15) * MAX_LENGTH_BASE;  // 0 → 50%
    } else {
        lengthScore = MAX_LENGTH_BASE + (length - 15) * BONUS_PER_CHAR;
        // Ограничиваем сверху 65%
        if (lengthScore > MAX_LENGTH_TOTAL) {
            lengthScore = MAX_LENGTH_TOTAL;
        }
    }

    // 1.1 Уникальные символы. Если меньше 5 - длинна не учитывается
    const uniqChars = new Set(phrase).size
    score += uniqChars;
    if (uniqChars > 5) {
        score += lengthScore;
    }

    // 2. Регистр букв (любой язык)
    const hasLower = /\p{Ll}/u.test(phrase);
    const hasUpper = /\p{Lu}/u.test(phrase);
    const caseScore = (hasLower && hasUpper) ? MAX_CASES :
        (hasLower || hasUpper) ? MAX_CASES / 2 : 0;
    score += caseScore;

    // 3. Цифры
    const hasDigits = /\d/.test(phrase);
    score += hasDigits ? MAX_DIGITS : 0;

    // 4. Спецсимволы и пробелы
    const hasSpecial = /[\p{Z}\p{P}\p{S}]/u.test(phrase);
    score += hasSpecial ? MAX_SPECIAL : 0;

    // 5. Бонус за выполнение всех условий
    const allMet = length >= 15 && hasLower && hasUpper && hasDigits && hasSpecial;
    if (allMet) {
        score += BONUS_ALL;
    }

    // Итоговый потолок — 100%
    score = Math.round(score);
    score = Math.min(100, score);

    // Обновление прогресс-бара
    progressBar.style.width = score + '%';
    if (typeof scorePassphrase !== 'undefined') {
        scorePassphrase = score;
    }

    let color;
    if (score < 30) color = '#ff4444';
    else if (score < 60) color = '#ff8c00';
    else if (score < 80) color = '#ccbb00';
    else if (score < 95) color = '#99cc00';
    else color = '#33aa33';

    progressBar.style.background = color;
}

function localStorageGet(keyName) {
    try {
        return localStorage.getItem(keyName);
    } catch (e) {
        return false;
    }
}

function sessionStorageGet(keyName) {
    try {
        return sessionStorage.getItem(keyName);
    } catch (e) {
        return false;
    }
}

function localStorageSet(keyName,value) {
    try {
        localStorage.setItem(keyName, value);
        return true;
    } catch (e) {
        return false;
    }
}

function sessionStorageSet(keyName,value) {
    try {
        sessionStorage.setItem(keyName, value);
        return true;
    } catch (e) {
        return false;
    }
}

function localStorageRemove(keyName) {
    try {
        return localStorage.removeItem(keyName);
    } catch (e) {
        return false;
    }
}

function sessionStorageRemove(keyName) {
    try {
        return sessionStorage.removeItem(keyName);
    } catch (e) {
        return false;
    }
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// === 1. Регистрация учётной записи (один раз) ===
async function registerCredential() {
    const salt = await crypto.getRandomValues(new Uint8Array(8));
    const randId = arrayBufferToBase64(salt).slice(0,3);

    let cred;
    try {
        cred = await navigator.credentials.create({
            publicKey: {
                challenge: await crypto.getRandomValues(new Uint8Array(32)),
                rp: {name: 'SMemo Service', id: location.hostname},
                user: {
                    id: await crypto.getRandomValues(new Uint8Array(16)),
                    name: "SMemo User " + randId,
                    displayName: "SMemo user"
                },
                pubKeyCredParams: [
                    {alg: -8, type: "public-key"},   // EdDSA (современный, предпочтительный)
                    {alg: -7, type: "public-key"},   // ES256 (базовый, широкий охват)
                    {alg: -257, type: "public-key"}, // RS256 (legacy RSA)
                ],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required",
                    residentKey: "required"
                },
                extensions: {
                    prf: {eval: {first: salt}},
                    hmacCreateSecret: true
                }
            }
        });
    } catch (err) {
    console.warn("registerCredential():", err.name, err.message);

    switch (err.name) {
        case "NotAllowedError":
            alert("Вы отменили создание passkey");
            break;
        case "InvalidStateError":
            alert("У вас уже есть passkey для этого сайта. Попробуйте войти.");
            break;
        case "NotSupportedError":
            alert("Ваше устройство или браузер не поддерживает passkey");
            break;
        default:
            alert("Ошибка создания passkey: " + err.message);
    }
    return false;
}

    localStorageSet("credId", arrayBufferToBase64(cred.rawId));
    localStorageSet("salt", arrayBufferToBase64(salt));
    return arrayBufferToBase64(cred.rawId);
}

async function getBioKeyFromUser(){
    const credId = localStorageGet("credId");
    const salt = localStorageGet("salt");
    if (!credId || !salt) {
        console.log('getBioKey: в localStorage нет сохраненных данных (credId, salt) для запроса ключа биометрии');
        return false; // нет данных для запроса ключа биометрии
    }

    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: {
                challenge: await crypto.getRandomValues(new Uint8Array(32)),
                allowCredentials: [{
                    type: "public-key",
                    id: base64ToArrayBuffer(credId)
                }],
                userVerification: "required",
                extensions: {
                    prf: {eval: {first: base64ToArrayBuffer(salt)}},
                    hmacCreateSecret: true
                }
            }
        });
    } catch (err) {
        /*
        switch (err.name) {
            case "NotAllowedError":
                alert("Вы отменили создание passkey");
                break;
            case "InvalidStateError":
                alert("У вас уже есть passkey для этого сайта. Попробуйте войти.");
                break;
            case "NotSupportedError":
                alert("Ваше устройство или браузер не поддерживает passkey");
                break;
            default:
                alert("Ошибка создания passkey: " + err.message);
        }
        */
        console.warn("Ошибка получения ключа биометрии от пользователя (" + err.name + "): "+err.message);
        return false;
    }

    const ext = assertion.getClientExtensionResults();
    let rawKey;
    if (ext.prf?.results?.first) {
        rawKey = ext.prf.results.first;                    // 32 байта
    } else if (ext.hmacCreateSecret === true) {
        rawKey = assertion.response.signature;             // тоже 32 байта
    } else {
        console.log("getBioKey: не удалось получить rawKey");
        return false;
    }
    return rawKey; // БАЙТЫ!
}

async function getBioKey(){
    let bioKey = sessionStorageGet('bioKey');
    if (bioKey) {
        console.log('getBioKey: bioKey найден в sessionStorage');
        return base64ToArrayBuffer(bioKey); // Возвращаем сразу БАЙТЫ!
    }
        console.log('getBioKey: bioKey нет в sessionStorage нужно запросить bioKey у пользователя');
        bioKey = await getBioKeyFromUser(); // Биометрического ключа нет в session, запросим у пользователя
        if (bioKey) {
            sessionStorageSet('bioKey', arrayBufferToBase64(bioKey)); // arrayBufferToBase64 правильно?? или не buffer
            console.log('getBioKey: bioKey получен, записан в sessionStorage');
            return bioKey; // БАЙТЫ!
        } else {
            // TODO: сюда не попадем, т.к. в случае ошибки с ключом вылетим по исключению!
            console.log('debug: не получилось получить ключ биометрии');
        }
}

async function updateSecretIcons(targetIds) {
    const value = event.currentTarget.value; // функция вызывается через .addEventListener('input'

    let icons = '';
    if (value) {
        const hash = await sha256(value);
        icons = await sha256ToIcons(hash, 4);
    }

    // Поддерживаем и строку, и массив
    const ids = Array.isArray(targetIds) ? targetIds : [targetIds];

    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = icons;
    });
}

/**
 * Генерирует ключи из парольной фразы
 * @param passphrase
 * @returns {Promise<(string|CryptoKey|{encodeForIndex: function(*): Promise<string>, codesLen: number})[]>}
 */
async function genKeys(passphrase) {
    let encryptionKey = await deriveClientKeyHex(passphrase, await sha256(passphrase), 100000); // делаем "дорогим" прямой перебор
    let encryptionKey2 = await sha256(encryptionKey); // "второй" хеш
    const secretKey = encryptionKey2.slice(-15); // последние 15 символов
    encryptionKey2 = await sha256(encryptionKey2); // "второй" хеш
    const aesSalt = encryptionKey2.slice(-15); // соль для шифрования - 15 знаков
    encryptionKey2 = await sha256(encryptionKey2); // "второй" хеш
    const login = encryptionKey2.slice(-15); // идентификатор пользователя - 15 знаков
    const aesKey = await getAesKey(encryptionKey, aesSalt);
    const ENC = await makeEncState(encryptionKey); // Инициация детерминированного шифрования
    return [login, secretKey, aesKey, ENC];
}

/**
 * Универсальное пакетное обновление DOM-элементов
 * Поддерживает:
 *   - простые свойства (value, disabled, textContent)
 *   - вложенные (style.width, style.backgroundColor)
 *   - dataset (dataset.id)
 *   - classList.add/remove/toggle
 */
function updateElements(updates) {
    // Если передан один набор — оборачиваем в массив
    const list = Array.isArray(updates) && !Array.isArray(updates[0]) ? [updates] : updates;

    for (const item of list) {
        // item должен быть массивом длиной 3 или 4
        if (!Array.isArray(item) || item.length < 3 || item.length > 4) {
            console.warn('batchUpdate: неверный формат элемента:', item);
            continue;
        }

        let targetIds = item[0];
        const path = item[1];
        const value = item[2];
        /** @type {string} */
        const method = item[3]; // опционально: 'add', 'remove', 'toggle'

        // Нормализуем IDs → всегда массив
        if (!Array.isArray(targetIds)) {
            targetIds = [targetIds];
        }

        for (const id of targetIds) {
            if (!id) continue;

            const el = document.getElementById(id);
            if (!el) {
                console.warn(`batchUpdate: элемент #${id ? ' #' + id : ''} не найден`);
                continue;
            }

            try {
                // 1. Простое свойство без точки
                if (typeof path === 'string' && !path.includes('.')) {
                    if (path === 'classList' && ['add', 'remove', 'toggle'].includes(method)) {
                        el.classList[method](value);
                    } else if (path in el) {
                        el[path] = value;
                    } else {
                        el.setAttribute(path, value);
                    }
                    continue;
                }

                // 2. Точечная нотация: style.width, dataset.xxx
                if (typeof path === 'string' && path.includes('.')) {
                    const parts = path.split('.');
                    let current = el;

                    for (let i = 0; i < parts.length - 1; i++) {
                        current = current[parts[i]];
                        if (!current) {
                            console.warn(`batchUpdate: ошибка при установке ${path} у #${id}`);
                            return false;
                        }
                    }

                    current[parts[parts.length - 1]] = value;
                    //continue;
                }

            } catch (err) {
                console.warn(`batchUpdate: ошибка при установке ${path} у #${id}`, err);
            }
        }
    }
}

/**
 * Проверяет, не превысит ли JSON-пayload заданный лимит в байтах
 * @param {Object} payload - объект, который будет отправлен через JSON.stringify
 * @param {number} maxBytes - максимальный размер в байтах (например, 5 МБ = 5 * 1024 * 1024)
 * @returns {boolean} true — помещается, false — слишком большой
 */
function isPayloadTooLarge(payload, maxBytes = 4 * 1024 * 1024) {
    try {
        const jsonString = JSON.stringify(payload);
        const byteLength = new TextEncoder().encode(jsonString).length;
        return byteLength > maxBytes;
    } catch (e) {
        // Если что-то сломалось — лучше отправить и пусть сервер откажет
        console.warn('Не удалось оценить размер payload', e);
        return false;
    }
}

function expandTags(text) {
    // Разбиваем по запятым и пробелам — универсально
    const tags = text
        .split(/\s*,\s*|\s+/)   // разделяем по "," или пробелам
        .map(t => t.trim())
        .filter(Boolean);

    const result = new Set(tags); // добавляем все исходные теги

    // Проходим по каждому тегу и добавляем части от тех, что с подчёркиванием
    tags.forEach(tag => {
        if (tag.includes('_')) {
            tag.split('_')
                .map(part => part.trim())
                .filter(Boolean)
                .forEach(part => result.add(part));
        }
    });

    // Возвращаем отсортированный список без дублей
    return Array.from(result).join(', ');
}






