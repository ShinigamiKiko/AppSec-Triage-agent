const _ = require('lodash');
const app = require('../src/server');

// Test-only helper: builds expected bodies with a template.
const expected = _.template('Hello <%= data.name %>!', { variable: 'data' });

module.exports = { app, expected: expected({ name: 'guest' }) };
