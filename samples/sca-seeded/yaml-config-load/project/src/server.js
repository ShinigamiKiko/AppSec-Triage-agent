const express = require('express');
const config = require('./config');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ service: config.name, status: 'ok' });
});

app.listen(config.port);
