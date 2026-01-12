import express from "express";

const app = express();
const PORT = process.env.PORT;

app.get("/", (_, res) => {
  res.send("Hello, the server is alive!!");
});

app.listen(PORT, () => {
  console.log(`Server started at http://localhost:${PORT}/`);
});
