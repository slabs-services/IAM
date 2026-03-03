import fs from "fs";
import jwt from "jsonwebtoken";
import { BYTELAKE_API, CLOUDFUNCTIONS_API } from "../Utils.js";
import { v4 as uuidv4 } from "uuid";

const privateKey = fs.readFileSync("keys/priv.key", "utf8");

export async function GenerateSTSToken(req, res) {
  const roleId = req.query.roleId;
  const expiresIn = req.query.expiresIn || 600;

  if(expiresIn > 1800) {
    return res.status(400).send({ error: "expiresIn cannot be greater than 30 minutes" });
  }

  if (!roleId) {
    return res.status(400).send({ error: "Missing roleId query parameter" });
  }

  const [roleInfo] = await req.server.db.query(
    "SELECT fsId, targetURN FROM roleFS WHERE roleId = ? AND isActive = 1",
    [roleId]
  );

  if (roleInfo.length === 0) {
    return res.status(404).send({ error: "Role not found" });
  }

  const token = jwt.sign({
    roles: roleInfo,
    singleTarget: false
  }, privateKey, {
    algorithm: "RS256",
    expiresIn: expiresIn + "s",
  });

  return res.send({ token });
}

export async function GenerateTimedTokens(req, res) {
  const resourceName = req.query.resourceName;
  const fsId = req.query.fsId;
  const expiresIn = req.query.expiresIn || 600;
  const maxUsages = req.query.maxUsages || 0;

  if (!fsId) {
    return res.status(400).send({ error: "Missing roleId or fsId query parameter" });
  }

  const [fsGroups] = await req.server.db.query("SELECT fsGroupId FROM fs WHERE id = ?", [fsId]);
  const application = fsGroups[0].fsGroupId;

  if(application === "urn:slabs:iam:fsgroup:bytelake"){
    const response = await fetch(BYTELAKE_API + "/checkOwner?resourceName=" + resourceName + "&accountRequested=" + req.userId);
    
    if(response.status !== 200){
      return res.status(401).send({ error: "This account does not own this resource." });
    }
  }else if(application === "urn:slabs:iam:fsgroup:cloudfunctions"){
    const response = await fetch(CLOUDFUNCTIONS_API + "/checkOwner?resourceName=" + resourceName + "&accountRequested=" + req.userId);
    
    if(response.status !== 200){
      return res.status(401).send({ error: "This account does not own this resource." });
    }
  }

  const token = jwt.sign({
    userId: req.userId,
    resourceName,
    fsId,
    singleTarget: true,
    maxUsages
  }, privateKey, {
    algorithm: "RS256",
    jwtid: uuidv4(),
    expiresIn: expiresIn + "s",
  });

  return res.send({ token });
}

export async function useTokenWithTRL(req, res) {
  const token = req.query.tui;
  const maxUsages = req.query.maxUsages;
  const expiresAt = req.query.expiresAt;

  if (!token || !maxUsages || !expiresAt) {
    return res.status(400).send({ error: "Missing token or maxUsages or expiresAt in request body" });
  }

  try {
    const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ?", [token]);

    if(trlInfo.length === 0){
      await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt) VALUES (?, ?, ?, ?)", [token, 1, new Date(), new Date(expiresAt*1000)]);

      return { isAllowed: true };
    }else{
      const currentUsages = trlInfo[0].usages;

      if(currentUsages >= maxUsages){
        return res.status(401).send({ isAllowed: false });
      }

      await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ?", [currentUsages + 1, token]);
      return { isAllowed: true };
    }

  } catch (err) {
    console.error("Error occurred while fetching TRL info:", err);
    return res.status(500).send({ error: "Internal server error" });
  }
}