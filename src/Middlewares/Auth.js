import jwt from "jsonwebtoken";
import { getPubKey } from "../Utils.js";

export async function authMiddlewareServices(req, res) {
  if(req.host !== "trust.iam.slabs.pt"){
    res.status(403).send({ error: "Forbidden" });
    return;
  }

  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.decode(token, { complete: true });

    const keyInfo = await req.server.db.query("SELECT pubKey FROM service WHERE id = ? AND isActive = 1", [decoded.header.kid]);

    const pubKey = await fetch("http://iam-keys.lake.tryspacelabs.pt/" + keyInfo[0][0].pubKey).then(res => res.text());

    jwt.verify(token, pubKey, {
      algorithms: ["RS256"],
    });
  } catch (err) {
    console.error("Authentication error:", err);
    return res.status(401).send({ error: "Invalid or expired token" });
  }
}

export async function authMiddlewareUser(req, res) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];

    const pubKey = await getPubKey();

    const decoded = jwt.verify(token, pubKey, {
      algorithms: ["RS256"],
    });

    if(decoded.isLimited && req.url !== "/generateOTP" && req.url !== "/validateOTP"){
      return res.status(401).send({ error: "Missing OTP Activation" });
    }

    req.userId = decoded.userId;
  } catch (err) {
    return res.status(401).send({ error: "Invalid or expired token" });
  }
}