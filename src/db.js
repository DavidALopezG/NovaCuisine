// src/db.js
const { Pool } = require("pg");
require("dotenv").config();
const { requireEnv } = require("./config/env");

const pool = new Pool({
  user:     process.env.DB_USER     || "postgres",
  host:     process.env.DB_HOST     || "localhost",
  database: process.env.DB_NAME     || "NOVACUISINE1",
  password: requireEnv("DB_PASSWORD"), // antes tenía un password real hardcodeado aquí
  port:     parseInt(process.env.DB_PORT || "5433"),
});

module.exports = pool;
