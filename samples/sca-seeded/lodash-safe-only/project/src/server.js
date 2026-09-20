const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.post('/profile', (req, res) => {
  const profile = _.pick(req.body, ['name', 'email']);
  const tags = _.map(req.body.tags || [], (tag) => String(tag).trim());
  res.json({ ...profile, tags: _.uniq(tags) });
});

app.listen(3000);
