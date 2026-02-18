import fs from "fs";
import jwt from "jsonwebtoken";
import { BYTELAKE_API, CLOUDFUNCTIONS_API } from "../Utils.js";

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

  if (!fsId) {
    return res.status(400).send({ error: "Missing roleId or fsId query parameter" });
  }

  const [fsGroups] = await req.server.db.query("SELECT fsGroup.id as fsGroupId FROM fs INNER JOIN fsGroup ON fs.fsGroupId = fsGroup.id WHERE fs.id = ?", [fsId]);
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
    singleTarget: true
  }, privateKey, {
    algorithm: "RS256",
    expiresIn: expiresIn + "s",
  });

  return res.send({ token });
}