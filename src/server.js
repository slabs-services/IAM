import Fastify from 'fastify';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { GenerateSTSToken, GenerateTimedTokens } from './routes/Services.js';
import { authMiddlewareServices, authMiddlewareUser } from './Middlewares/Auth.js';
import { ActivateOTP, CreateAccount, GenerateOTP, Login } from './routes/User.js';
dotenv.config();

const fastify = Fastify();

const connection = await mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD
});

fastify.decorate("db", connection);

fastify.post('/createAccount', CreateAccount);
fastify.post('/validateOTP', { preHandler: authMiddlewareUser }, ActivateOTP);
fastify.post('/generateOTP', { preHandler: authMiddlewareUser }, GenerateOTP);
fastify.post('/login', Login);
fastify.get('/getSTS', { preHandler: authMiddlewareServices }, GenerateSTSToken);
fastify.post('/timedTokens', { preHandler: authMiddlewareUser }, GenerateTimedTokens);
fastify.post('/timedTokensServices', { preHandler: authMiddlewareServices }, GenerateTimedTokens);

await fastify.listen({ host: '127.0.0.1', port: 8080 });