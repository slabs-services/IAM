import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { privateKey } from "../Utils.js";

export async function LoginSA(req, reply) {
    const auth = req.headers.authorization;

    if (!auth || !auth.startsWith("Basic ")) {
        reply.header("WWW-Authenticate", 'Basic realm="Service Account"').code(401);
        return { message: "Authentication required." };
    }

    const decodedAuth = Buffer.from(auth.split(" ")[1], "base64").toString("utf-8");
    const [username, password] = decodedAuth.split(":");

    if (!username || !password) {
        reply.header("WWW-Authenticate", 'Basic realm="Service Account"').code(401);
        return { message: "Missing username or password." };
    }

    const [rows] = await req.server.db.query(
        "SELECT accountId, password FROM serviceaccount WHERE username = ? AND isActive = 1 LIMIT 1",
        [username]
    );

    if (rows.length === 0) {
        reply.header("WWW-Authenticate", 'Basic realm="Service Account"').code(401);
        return { message: "Invalid service account." };
    }

    const isPasswordValid = await bcrypt.compare(password, rows[0].password);

    if (!isPasswordValid) {
        reply.header("WWW-Authenticate", 'Basic realm="Service Account"').code(401);
        return { message: "Username or password invalid." };
    }

    const token = jwt.sign({
        userId: rows[0].accountId
    }, privateKey, {
        algorithm: "RS256",
        expiresIn: "5h"
    });

    return { token };
}