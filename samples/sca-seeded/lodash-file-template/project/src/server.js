const express = require('express');
const { welcomeEmail } = require('./mailer');

const app = express();
app.use(express.json());

// User input reaches the rendered data, never the template source or its options.
app.post('/welcome', (req, res) => {
  res.send(welcomeEmail(req.body));
});

app.listen(3000);
