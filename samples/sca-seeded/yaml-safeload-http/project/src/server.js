const express = require('express');
const yaml = require('js-yaml');

const app = express();
app.use(express.text({ type: 'application/yaml' }));

app.post('/import', (req, res) => {
  const doc = yaml.safeLoad(req.body);
  res.json({ keys: Object.keys(doc || {}) });
});

app.listen(3000);
