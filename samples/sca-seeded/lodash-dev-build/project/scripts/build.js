// Build-time only: renders static pages into dist/ before deployment.
const fs = require('fs');
const path = require('path');
const _ = require('lodash');

const source = fs.readFileSync(path.join(__dirname, 'page.tpl'), 'utf8');
const render = _.template(source, { variable: 'data' });

fs.mkdirSync(path.join(__dirname, '..', 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, '..', 'dist', 'index.html'), render({ title: 'Home' }));
