const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 8082;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Server is running');
});

app.listen(PORT, () => {
  console.log('Server is running on http://localhost:8082');
});