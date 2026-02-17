export const BYTELAKE_API = "http://storage.bytelake.slabs.pt";
export const CLOUDFUNCTIONS_API = "http://scheduler.cloudfunctions.slabs.pt";

export function validateEmail(email) {
    let atIndex = email.indexOf("@");
    if (atIndex < 1 || atIndex !== email.lastIndexOf("@")){
        return false;
    }

    let [_, domain] = email.split("@");

    let dotIndex = domain.lastIndexOf(".");
    if (dotIndex < 1 || dotIndex === domain.length - 1){
        return false;
    }

    if (email.includes(" ") || email.includes("..")){
        return false;
    }

    return true;
}

let cachedKey = null;

export async function getPubKey() {
  if (cachedKey){
    return cachedKey;
  }

  const res = await fetch("http://iam-keys.lake.tryspacelabs.pt/69e38991-6131-483d-b773-84586123b912.key");
  cachedKey = await res.text();
  return cachedKey;
}