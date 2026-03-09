import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { privateKey } from "../Utils.js";

export async function LoginSA(req, reply) {
    const username = req.body?.username.trim();
    const password = req.body?.password ?? "";

    if (typeof password !== "string" || password.length < 8) {
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const [rows] = await req.server.db.query(
        "SELECT id, password FROM serviceaccount WHERE email = ? AND isActive = 1 LIMIT 1",
        [username]
    );

    if (rows.length === 0) {
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const isPasswordValid = await bcrypt.compare(password, rows[0].password);

    if(!isPasswordValid){
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const token = jwt.sign({
        userId: rows[0].id, // ver isto hoje
        isLimited: true
    }, privateKey, {
        algorithm: "RS256",
        expiresIn: "5m"
    });

    return {
        token,
        redirectToOTP: !rows[0].otpEnable
    }
}