const _ = require('lodash');

// The `variable` option comes from the request two frames up — CVE-2021-23337.
function renderGreeting(settings) {
  const compiled = _.template('Hello <%= data.name %>!', { variable: settings.variable });
  return compiled({ name: settings.name });
}

module.exports = { renderGreeting };
