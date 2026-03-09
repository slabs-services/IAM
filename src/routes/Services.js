import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { privateKey } from "../Utils.js";

export async function GenerateSTSToken(req, res) {
  const sourceId = req.query.sourceId;
  const expiresIn = req.query.expiresIn || 600;
  const source = req.query.source;

  if(source !== "role" && source !== "serviceaccount"){
    return res.status(400).send({ error: "Invalid source system" });
  }

  if(expiresIn > 1800) {
    return res.status(400).send({ error: "expiresIn cannot be greater than 30 minutes" });
  }

  if (!sourceId) {
    return res.status(400).send({ error: "Missing sourceId query parameter" });
  }

  const [roleInfo] = await req.server.db.query(
    "SELECT fsId, targetURN, roleFsExtras.name, roleFsExtras.value FROM associatedFS LEFT JOIN roleFsExtras ON associatedFS.id = roleFsExtras.roleFsId WHERE sourceId = ? AND isActive = 1 AND source = ?",
    [sourceId, source]
  );

  if (roleInfo.length === 0) {
    return res.status(404).send({ error: "Role not found" });
  }

  const groupedRolesMap = new Map();

  for (const row of roleInfo) {
    const key = `${row.fsId}|${row.targetURN}`;

    if (!groupedRolesMap.has(key)) {
      groupedRolesMap.set(key, {
        fsId: row.fsId,
        targetURN: row.targetURN,
        extras: []
      });
    }

    if (row.name !== null) {
      groupedRolesMap.get(key).extras.push({
        name: row.name,
        value: row.value
      });
    }
  }

  const roles = Array.from(groupedRolesMap.values());

  const token = jwt.sign({
    roles,
    singleTarget: false
  }, privateKey, {
    algorithm: "RS256",
    expiresIn: expiresIn + "s",
  });

  return res.send({ token });
}

export async function GenerateTimedTokens(req, res) {
  const resourceName = req.body.resourceName;
  const fsId = req.body.fsId;
  const expiresIn = req.body.expiresIn || 600;
  const extras = req.body.extras || {};

  if (!fsId) {
    return res.status(400).send({ error: "Missing fsId query parameter" });
  }

  const [fsGroups] = await req.server.db.query("SELECT fsGroupId, ownerEndpoint FROM fs INNER JOIN fsGroup ON fs.fsGroupId = fsGroup.id WHERE fs.id = ?", [fsId]);
  const application = fsGroups[0].fsGroupId;

  if(application === "urn:slabs:iam:fsgroup:bytelake"){
    const response = await fetch("http://" + fsGroups[0].ownerEndpoint + "/checkOwner?resourceName=" + resourceName + "&accountRequested=" + req.userId);
    
    if(response.status !== 200){
      return res.status(401).send({ error: "This account does not own this resource." });
    }
  }

  const token = jwt.sign({
    userId: req.userId,
    resourceName,
    fsId,
    singleTarget: true,
    extras
  }, privateKey, {
    algorithm: "RS256",
    jwtid: uuidv4(),
    expiresIn: expiresIn + "s",
  });

  return { token };
}