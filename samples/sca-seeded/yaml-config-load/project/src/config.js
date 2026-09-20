const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const config = yaml.load(fs.readFileSync(path.join(__dirname, '..', 'config.yml'), 'utf8'));

module.exports = config;
