const express = require('express');
const { renderGreeting } = require('./render');

const app = express();
app.use(express.json());

app.post('/greeting', (req, res) => {
  const settings = { variable: req.body.variable, name: req.body.name };
  res.send(renderGreeting(settings));
});

app.listen(3000);
