const express = require('express');

// A JSON API. Nothing here renders a user interface: react sits in
// package.json from a prototype nobody removed.
const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(3000);
