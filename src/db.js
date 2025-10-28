// src/db.js
const { Pool } = require("pg");

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "NovaCuisine",
  password: "dafrangus2002",
  port: 5433,
});

module.exports = pool;
