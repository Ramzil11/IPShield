#!/usr/bin/env node
/**
 * Реальный сетевой стенд проверки утечки IP (Live Leak Probe)
 *
 * Как использовать:
 * 1. Включите VPN (Happ) и убедитесь, что в IPShield добавлено правило с процессом:
 *    `leak-probe.js` (и/или доменом `checkip.amazonaws.com`).
 * 2. Запустите этот скрипт в терминале:
 *    npm run probe
 * 3. Пока скрипт непрерывно шлёт реальные HTTPS-запросы на внешний сервер,
 *    выключите VPN в Happ, подождите пару секунд и включите обратно.
 * 4. Скрипт покажет, увидел ли внешний сервер хотя бы один запрос с вашим домашним IP.
 */

const https = require('https');

const TARGET_URL = 'https://checkip.amazonaws.com';
const INTERVAL_MS = 350;

let expectedVpnIp = process.argv[2] || null;
let seq = 0;
let validCount = 0;
let blockedCount = 0;
let leakCount = 0;
let lastTickAt = Date.now();

function fetchExternalIpOnce() {
  return new Promise(resolve => {
    const start = Date.now();
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ...result, latencyMs: Date.now() - start });
    };

    const req = https.get(
      `${TARGET_URL}?_=${Date.now()}`,
      {
        family: 4,
        agent: false,
        timeout: 1800,
        headers: {
          Connection: 'close',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'User-Agent': 'IPShield-LeakProbe/1.0'
        }
      },
      res => {
        let body = '';
        res.on('data', chunk => (body += chunk));
        res.on('end', () => {
          res.destroy();
          const ip = body.trim();
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            finish({ ok: true, ip });
          } else {
            finish({ ok: false, reason: 'INVALID_RESPONSE' });
          }
        });
      }
    );

    const timer = setTimeout(() => {
      try {
        req.destroy();
      } catch {}
      finish({ ok: false, reason: 'TIMEOUT' });
    }, 1900);

    req.on('error', err => {
      finish({ ok: false, reason: err.code || err.message || 'NETWORK_ERROR' });
    });
  });
}

async function runProbe() {
  console.log('================================================================');
  console.log('🛡️  IPShield — Реальный сетевой тест на утечку IP (Leak Probe)');
  console.log(`📌 PID процесса: ${process.pid} | Процесс для правила: leak-probe.js`);
  console.log(`🌐 Внешний эхо-сервер («вторая сторона»): ${TARGET_URL}`);
  console.log('================================================================');

  if (!expectedVpnIp) {
    console.log('⏳ Определяем текущий эталонный VPN IP...');
    const initRes = await fetchExternalIpOnce();
    if (!initRes.ok) {
      console.error(`❌ Не удалось получить стартовый IP (${initRes.reason}). Включите VPN и попробуйте снова.`);
      process.exit(1);
    }
    expectedVpnIp = initRes.ip;
  }

  console.log(`✅ Эталонный (разрешённый) VPN IP: ${expectedVpnIp}`);
  console.log('👉 Добавьте в IPShield процесс "leak-probe.js" или домен "checkip.amazonaws.com",');
  console.log('   затем выключите и снова включите Happ VPN во время работы скрипта.\n');

  lastTickAt = Date.now();

  while (true) {
    const now = Date.now();
    const gapMs = now - lastTickAt;
    if (gapMs > INTERVAL_MS + 1500) {
      console.log(
        `\n❄️ -> ▶️  [ProcessGuard] Процесс был ЗАМОРОЖЕН (SIGSTOP) на ${(gapMs / 1000).toFixed(1)} сек (0 пакетов отправлено) и только что разморожен!\n`
      );
    }

    seq++;
    const res = await fetchExternalIpOnce();
    lastTickAt = Date.now();

    if (res.ok) {
      if (res.ip === expectedVpnIp) {
        validCount++;
        console.log(
          `🟢 [#${seq}] Сервер увидел эталонный VPN IP: ${res.ip} (${res.latencyMs} мс) | Утечек: ${leakCount}`
        );
      } else {
        leakCount++;
        console.log(
          `🚨 [#${seq}] УТЕЧКА IP! Вторая сторона увидела НЕВАЛИДНЫЙ IP: ${res.ip} (ожидался ${expectedVpnIp}) | Всего утечек: ${leakCount}`
        );
      }
    } else {
      blockedCount++;
      console.log(
        `🛡️  [#${seq}] Трафик перехвачен / заблокирован (${res.reason}, ${res.latencyMs} мс) | Утечек: ${leakCount}`
      );
    }

    await new Promise(r => setTimeout(r, INTERVAL_MS));
  }
}

process.on('SIGINT', () => {
  console.log('\n================================================================');
  console.log(`📊 ИТОГ ТЕСТА:`);
  console.log(`   Успешных запросов с VPN IP (${expectedVpnIp}): ${validCount}`);
  console.log(`   Заблокировано сетевым экраном: ${blockedCount}`);
  console.log(`   Утечек реального IP на вторую сторону: ${leakCount}`);
  console.log('================================================================');
  process.exit(leakCount > 0 ? 1 : 0);
});

void runProbe();

