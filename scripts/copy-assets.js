const fs = require('fs');
const path = require('path');

const srcRenderer = path.join(__dirname, '../src/renderer');
const distRenderer = path.join(__dirname, '../dist/renderer');

if (!fs.existsSync(distRenderer)) {
  fs.mkdirSync(distRenderer, { recursive: true });
}

for (const file of ['index.html', 'styles.css']) {
  const from = path.join(srcRenderer, file);
  const to = path.join(distRenderer, file);
  if (fs.existsSync(from)) {
    fs.copyFileSync(from, to);
  }
}

