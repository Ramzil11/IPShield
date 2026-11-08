const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');

/**
 * Minimal pure-Node PNG encoder (RGBA 8-bit) so we don't need any external image libraries.
 */
function encodePng(width, height, rgbaBuffer) {
  const crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[n] = c >>> 0;
  }

  function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function makeChunk(type, data) {
    const typeBuf = Buffer.from(type, 'ascii');
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const crcInput = Buffer.concat([typeBuf, data]);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(crcInput), 0);
    return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  // Filter byte 0 per scanline
  const rawScanlines = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    const rowStart = y * (1 + width * 4);
    rawScanlines[rowStart] = 0;
    rgbaBuffer.copy(rawScanlines, rowStart + 1, y * width * 4, (y + 1) * width * 4);
  }

  const compressed = zlib.deflateSync(rawScanlines, { level: 9 });
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
}

function sdRoundedBox(px, py, cx, cy, hx, hy, rad) {
  const dx = Math.abs(px - cx) - hx + rad;
  const dy = Math.abs(py - cy) - hy + rad;
  return Math.hypot(Math.max(dx, 0), Math.max(dy, 0)) + Math.min(Math.max(dx, dy), 0) - rad;
}

function shieldSignedDistance(px, py, size) {
  const cx = size / 2;
  const topY = size * 0.21;
  const botY = size * 0.80;

  const t = Math.max(0, Math.min(1, (py - topY) / (botY - topY)));
  const maxHalfW = size * 0.27;
  const halfWidth = maxHalfW * Math.pow(1 - Math.pow(t, 1.85), 0.72);
  const dx = Math.abs(px - cx) - halfWidth;

  const topArch = topY + size * 0.025 * Math.pow(Math.abs(px - cx) / maxHalfW, 2);
  const dyTop = topArch - py;
  const dyBot = py - botY;

  return Math.max(dx, dyTop, dyBot);
}

function renderShieldAppIcon(size = 512) {
  const rgba = Buffer.alloc(size * size * 4, 0);
  const cx = size / 2;
  const cy = size / 2;
  const halfBox = size * 0.42;
  const cornerRad = size * 0.19;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const dSquircle = sdRoundedBox(x, y, cx, cy, halfBox, halfBox, cornerRad);

      if (dSquircle <= 1.0) {
        const bgCov = Math.min(1, Math.max(0, 1.0 - dSquircle));

        // Deep dark slate gradient background (#0F172A -> #090D16)
        const gradT = y / size;
        let r = Math.round(18 * (1 - gradT) + 9 * gradT);
        let g = Math.round(25 * (1 - gradT) + 13 * gradT);
        let b = Math.round(42 * (1 - gradT) + 22 * gradT);

        // Subtle inner border on squircle
        if (dSquircle > -size * 0.012) {
          r += 28;
          g += 38;
          b += 55;
        }

        // Radial glow behind shield
        const distCenter = Math.hypot(x - cx, y - cy) / (size * 0.4);
        if (distCenter < 1) {
          const glow = Math.pow(1 - distCenter, 2) * 0.35;
          r = Math.min(255, Math.round(r + 16 * glow));
          g = Math.min(255, Math.round(g + 185 * glow));
          b = Math.min(255, Math.round(b + 129 * glow));
        }

        // Draw Shield Emblem
        const dShield = shieldSignedDistance(x, y, size);
        if (dShield <= 1.2) {
          const sCov = Math.min(1, Math.max(0, 1.2 - dShield));
          const borderThickness = size * 0.038;
          const isBorder = dShield >= -borderThickness;
          const isRightInner = dShield < -borderThickness * 1.45 && x >= cx;

          // Emerald-Cyan shield colors (#10B981 / #34D399)
          const sr = isBorder ? 52 : isRightInner ? 16 : 16;
          const sg = isBorder ? 211 : isRightInner ? 185 : 185;
          const sb = isBorder ? 153 : isRightInner ? 129 : 129;
          const sAlpha = (isBorder ? 1.0 : isRightInner ? 0.85 : 0.28) * sCov;

          r = Math.round(r * (1 - sAlpha) + sr * sAlpha);
          g = Math.round(g * (1 - sAlpha) + sg * sAlpha);
          b = Math.round(b * (1 - sAlpha) + sb * sAlpha);
        }

        rgba[idx] = Math.min(255, r);
        rgba[idx + 1] = Math.min(255, g);
        rgba[idx + 2] = Math.min(255, b);
        rgba[idx + 3] = Math.round(bgCov * 255);
      }
    }
  }

  return encodePng(size, size, rgba);
}

const assetsDir = path.join(__dirname, '../assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir, { recursive: true });
}

const pngPath = path.join(assetsDir, 'icon.png');
const pngBuf = renderShieldAppIcon(512);
fs.writeFileSync(pngPath, pngBuf);
console.log('[Icon] Generated', pngPath);

// On macOS, also build assets/icon.icns and apply branding to local Electron.app for dev mode
if (process.platform === 'darwin') {
  const iconsetDir = path.join(assetsDir, 'icon.iconset');
  if (!fs.existsSync(iconsetDir)) {
    fs.mkdirSync(iconsetDir, { recursive: true });
  }

  const sizes = [16, 32, 128, 256, 512];
  for (const s of sizes) {
    execFileSync('sips', ['-z', String(s), String(s), pngPath, '--out', path.join(iconsetDir, `icon_${s}x${s}.png`)]);
    const s2 = s * 2;
    if (s2 <= 1024) {
      execFileSync('sips', ['-z', String(s2), String(s2), pngPath, '--out', path.join(iconsetDir, `icon_${s}x${s}@2x.png`)]);
    }
  }

  const icnsPath = path.join(assetsDir, 'icon.icns');
  execFileSync('iconutil', ['-c', 'icns', iconsetDir, '-o', icnsPath]);
  fs.rmSync(iconsetDir, { recursive: true, force: true });
  console.log('[Icon] Generated', icnsPath);

  // Patch dev Electron.app bundle so Dock & Menu Bar show "IPShield" and our Shield icon even in dev mode
  const electronAppDir = path.join(__dirname, '../node_modules/electron/dist/Electron.app/Contents');
  const plistPath = path.join(electronAppDir, 'Info.plist');
  const electronIcns = path.join(electronAppDir, 'Resources/electron.icns');

  if (fs.existsSync(electronIcns)) {
    fs.copyFileSync(icnsPath, electronIcns);
  }
  if (fs.existsSync(plistPath)) {
    let plist = fs.readFileSync(plistPath, 'utf-8');
    plist = plist.replace(
      /(<key>CFBundleDisplayName<\/key>\s*<string>)[^<]*(<\/string>)/,
      '$1IPShield$2'
    );
    plist = plist.replace(
      /(<key>CFBundleName<\/key>\s*<string>)[^<]*(<\/string>)/,
      '$1IPShield$2'
    );
    fs.writeFileSync(plistPath, plist, 'utf-8');
  }
  console.log('[Icon] Patched dev Electron.app with IPShield name and Shield icon');
}

