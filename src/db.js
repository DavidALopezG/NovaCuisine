// src/db.js
const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user:     process.env.DB_USER     || "postgres",
  host:     process.env.DB_HOST     || "localhost",
  database: process.env.DB_NAME     || "NOVACUISINE1",
  password: process.env.DB_PASSWORD || "dafrangus2002",
  port:     parseInt(process.env.DB_PORT || "5433"),
});

module.exports = pool;
