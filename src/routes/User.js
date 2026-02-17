import { validateEmail } from "../../Utils.js";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";
import fs from "fs";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";

const privateKey = fs.readFileSync("keys/priv-login.key", "utf8");

export async function CreateAccount(req, reply) {
  const email = (req.body?.email ?? "").trim().toLowerCase();
  const password = req.body?.password ?? "";

  if (!validateEmail(email)) {
    return reply.code(401).send({ message: "Email invalido." });
  }

  if (typeof password !== "string" || password.length < 8) {
    return reply.code(401).send({ message: "A password precisa de conter pelo menos 8 caracteres." });
  }

  const [rows] = await req.server.db.query(
    "SELECT id FROM accounts WHERE email = ? LIMIT 1",
    [email]
  );

  if (rows.length !== 0) {
    return reply.code(401).send({ message: "Já existe uma conta com este email." });
  }

  const id = "urn:slabs:accounts:" + uuidv4();
  const passwordHash = await bcrypt.hash(password, 12);

  await req.server.db.query(
    "INSERT INTO accounts (id, email, password, isActive, otpEnable) VALUES (?, ?, ?, ?, ?)",
    [id, email, passwordHash, 0, 0]
  );

  const token = jwt.sign({
    userId: id,
    isLimited: true
  }, privateKey, {
    algorithm: "RS256",
    expiresIn: "5m"
  });

  return reply.code(201).send({ token });
}

export async function GenerateOTP(req, res) {
    const userId = req.userId;

    const userData = await req.server.db.query("SELECT email, otpEnable FROM accounts WHERE id = ?", [userId]);

    if(userData[0][0].otpEnable){
        return res.code(401).send({ message: "Já existe um codigo OTP ativo." });
    }

    const secret = speakeasy.generateSecret({
        length: 20,
        name: "SLabs Cloud (" + userData[0][0].email + ")"
    });

    await req.server.db.query("UPDATE accounts SET otp = ? WHERE id = ? ", [secret.base32, userId]);

    return {
        qrCode: secret.otpauth_url
    }
}

export async function ActivateOTP(req, reply) {
    const userId = req.userId;
    const code = req.body.code;

    const userData = await req.server.db.query("SELECT otp, otpEnable, isActive FROM accounts WHERE id = ?", [userId]);

    const isValid = speakeasy.totp.verify({ secret: userData[0][0].otp, encoding: 'base32', token: code, window: 6 });

    if(!isValid){
        return reply.code(401).send({ message: "Codigo OTP invalido." });
    }

    if(userData[0][0].otpEnable){
        if(!userData[0][0].isActive){
            return reply.code(401).send({ message: "A sua conta não está ativa." });
        }

        const token = jwt.sign({
            userId
        }, privateKey, {
            algorithm: "RS256",
            expiresIn: "5h"
        });

        return {
            token
        }
    }else{
        await req.server.db.query("UPDATE accounts SET isActive = 1, otpEnable = 1 WHERE id = ? ", [userId]);

        const token = jwt.sign({
            userId
        }, privateKey, {
            algorithm: "RS256",
            expiresIn: "5h"
        });

        return {
            token
        }
    }
}

export async function Login(req, reply) {
    const email = (req.body?.email ?? "").trim().toLowerCase();
    const password = req.body?.password ?? "";

    if (!validateEmail(email)) {
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    if (typeof password !== "string" || password.length < 8) {
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const [rows] = await req.server.db.query(
        "SELECT id, password, otpEnable FROM accounts WHERE email = ? LIMIT 1",
        [email]
    );

    if (rows.length === 0) {
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const isPasswordValid = await bcrypt.compare(password, rows[0].password);

    if(!isPasswordValid){
        return reply.code(401).send({ message: "Email ou password invalidos." });
    }

    const token = jwt.sign({
        userId: rows[0].id,
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