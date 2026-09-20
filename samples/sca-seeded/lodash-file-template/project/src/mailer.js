const fs = require('fs');
const path = require('path');
const _ = require('lodash');

const source = fs.readFileSync(path.join(__dirname, 'templates', 'welcome.tpl'), 'utf8');
const render = _.template(source, { variable: 'data' });

function welcomeEmail(user) {
  return render({ name: user.name });
}

module.exports = { welcomeEmail };
