import pg from "pg"
ç
const { Pool } = pg

export const pool = new Pool({
	connectionString: process.env.DATABASE_URL
})