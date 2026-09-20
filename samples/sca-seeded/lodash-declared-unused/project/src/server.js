const express = require('express');

const app = express();
app.use(express.json());

app.post('/echo', (req, res) => {
  res.json({ received: Object.keys(req.body || {}) });
});

app.listen(3000);
