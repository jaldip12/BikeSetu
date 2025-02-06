const { Pool } = require('pg');
const axios = require("axios");

// Create a new PostgreSQL client with SSL configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,  // This allows insecure certificates, which is fine for many cloud-hosted databases.
    },
});

module.exports = async function(req, res) {
    try {
        const { prompt } = req.body;
        if(!prompt) {
            return res.status(400).json({ error: 'Prompt is required' });
        }
        const response = await axios.post(process.env.AIML_SERVER + '/recommend-bikes', { user_prompt: prompt });

        let sqlQuery = response.data.sql_query;

        sqlQuery = sqlQuery.replaceAll("```sql", "");
        sqlQuery = sqlQuery.replaceAll("```", "");


        // Log the query for debugging purposes
        console.log('Executing query:', sqlQuery);

        // Execute the raw query
        const result = await pool.query(sqlQuery);

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching bikes:', error);
        res.status(500).json({ error: 'An error occurred while fetching bikes' });
    }
}
