(() => {
  'use strict';

  const form = document.querySelector('form');
  const passwordField = document.getElementById('password');
  const submit = form.querySelector('button');
  const message = document.getElementById('message');
  const slot = form.dataset.slot;
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const encoder = new TextEncoder();
  const iterations = 600000;
  const download = document.getElementById('offline-copy');
  if (download && ['https:', 'http:'].includes(location.protocol)) download.hidden = false;
  // The short password form has no scroll range for the browser to restore.
  function positionKey() {
    let id = history.state?.journalPositionId;
    if (!id) {
      id = crypto.randomUUID();
      history.replaceState({ ...history.state, journalPositionId: id }, '');
    }
    return 'journal-view.1:' + id;
  }
  let previousScroll;
  try { previousScroll = JSON.parse(sessionStorage.getItem(positionKey())); } catch { /* Storage can be disabled. */ }

  function visiblePosition() {
    const position = { x: scrollX, y: scrollY };
    if (!scrollY) return position;
    let node = document.elementFromPoint(innerWidth / 2, innerHeight / 3);
    if (!node || !document.body.contains(node)) return position;
    const top = node.getBoundingClientRect().top;
    const path = [];
    while (node !== document.body) {
      const style = getComputedStyle(node);
      if (style.position === 'sticky' || style.position === 'fixed') return position;
      const parent = node.parentElement;
      path.unshift(Array.prototype.indexOf.call(parent.children, node));
      node = parent;
    }
    return { ...position, path, top };
  }

  function restorePosition() {
    if (Number.isFinite(previousScroll?.x) && Number.isFinite(previousScroll?.y)) {
      const { x, y, path, top } = previousScroll;
      const node = Array.isArray(path) && path.reduce((parent, index) => parent?.children[index], document.body);
      const offset = node && Number.isFinite(top) ? scrollY + node.getBoundingClientRect().top - top : y;
      window.scrollTo({ left: x, top: offset, behavior: 'instant' });
    } else if (location.hash) {
      let id;
      try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
      document.getElementById(id)?.scrollIntoView({ behavior: 'instant' });
    }
  }

  function restoreWhileLoading() {
    if (!previousScroll && !location.hash) return;
    const controller = new AbortController();
    const options = { capture: true, passive: true, signal: controller.signal };
    let frame = 0;
    function schedule() {
      if (controller.signal.aborted || frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        restorePosition();
      });
    }
    // Fonts, weather updates and the original scripts can all change the position
    // of the saved paragraph after the first paint. Follow it until the reader
    // takes control, including when the page is entered through a fragment.
    const size = new ResizeObserver(schedule);
    size.observe(document.documentElement);
    const content = new MutationObserver(schedule);
    content.observe(document.documentElement, { childList: true, subtree: true });
    function stop() {
      controller.abort();
      size.disconnect();
      content.disconnect();
      cancelAnimationFrame(frame);
    }
    for (const event of ['pointerdown', 'wheel', 'touchstart', 'keydown', 'focusin', 'hashchange', 'popstate', 'pagehide']) {
      window.addEventListener(event, stop, options);
    }
    window.addEventListener('load', schedule, { once: true, signal: controller.signal });
    document.fonts?.ready.then(schedule);
    schedule();
  }

  async function loadPackage() {
    const embedded = document.getElementById('sealed-page');
    if (embedded) {
      const binary = atob(embedded.textContent.trim());
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
      return bytes;
    }
    // A cached first-release gate still requests this script and its separate package.
    const response = await fetch(new URL('journal.bin', location.href), {
      cache: 'no-store', credentials: 'omit', redirect: 'error',
    });
    if (!response.ok) throw new Error('load');
    return new Uint8Array(await response.arrayBuffer());
  }

  async function openPage(password) {
    const file = await loadPackage();
    if (file.length < 49 || decoder.decode(file.subarray(0, 4)) !== 'JNL1') throw new Error('format');
    const passwordBytes = encoder.encode(password);
    let material;
    try {
      material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    } finally {
      passwordBytes.fill(0);
    }
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: file.subarray(4, 20), iterations, hash: 'SHA-256' }, material,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
    );
    const data = await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: file.subarray(20, 32), tagLength: 128,
      additionalData: encoder.encode('journal-page:1:' + slot + ':PBKDF2-SHA-256:' + iterations),
    }, key, file.subarray(32));
    const plaintext = new Uint8Array(data);
    try {
      const payload = JSON.parse(decoder.decode(plaintext));
      if ((slot !== 'a' && slot !== 'b') || typeof payload.html !== 'string' ||
          !Array.isArray(payload.keys) || payload.keys.length !== 2 ||
          !payload.keys.every(key => typeof key === 'string' && key.length)) {
        throw new Error('format');
      }
      return payload;
    } finally {
      plaintext.fill(0);
    }
  }

  async function unlock(event) {
    event.preventDefault();
    if (submit.disabled || !passwordField.value) return;
    submit.disabled = true;
    passwordField.readOnly = true;
    message.textContent = '正在解鎖…';
    let stage = 'open';
    try {
      const { html, keys } = await openPage(passwordField.value);
      stage = 'storage';
      await window.installJournalState(passwordField.value, keys, keys[slot === 'a' ? 0 : 1]);
      passwordField.value = '';
      document.open();
      document.write(html);
      document.close();
      restoreWhileLoading();
      window.addEventListener('hashchange', () => {
        try { positionKey(); } catch { /* History can be restricted. */ }
      });
      window.addEventListener('pagehide', () => {
        try {
          sessionStorage.setItem(positionKey(), JSON.stringify(visiblePosition()));
        } catch { /* The journal also works without browser storage. */ }
      });
      window.addEventListener('pageshow', event => {
        if (event.persisted) location.reload();
      });
    } catch {
      passwordField.value = '';
      passwordField.readOnly = false;
      submit.disabled = false;
      message.textContent = stage === 'storage'
        ? '無法安全開啟瀏覽器儲存的紀錄。請保留原有資料，再試一次。'
        : '無法解鎖日誌。請確認密碼，再試一次。';
      passwordField.focus();
    }
  }

  form.addEventListener('submit', unlock);
  if (globalThis.crypto?.subtle && typeof window.installJournalState === 'function') {
    submit.disabled = false;
  } else {
    message.textContent = '無法載入解鎖功能。請使用支援加密功能的瀏覽器開啟下載的 HTML 檔，或透過 HTTPS 開啟本頁。';
  }
})();
