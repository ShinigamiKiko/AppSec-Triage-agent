const express = require('express');

const app = express();
app.use(express.json());

app.post('/greeting', (req, res) => {
  res.send(`Hello ${String(req.body.name || 'guest')}!`);
});

module.exports = app;
