#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { webcrypto } from "crypto";
import path from "node:path";

const { importKey, exportKey } = (webcrypto as any).subtle as SubtleCrypto;

function pemToBuffer(pem: string): Buffer {
  const unwrapped = pem.replace(/-{5}(BEGIN|END).*-{5}/g, "");
  return Buffer.from(unwrapped, "base64");
}

async function bufferToJsonWebKey(keyData: Buffer): Promise<JsonWebKey> {
  const algorithm = {
    name: "RSA-PSS",
    hash: "SHA-256",
  };
  const cryptoKey = await importKey("pkcs8", keyData, algorithm, true, [
    "sign",
  ]);
  return await exportKey("jwk", cryptoKey);
}

async function pemToJwk(argv: string[]): Promise<void> {
  let [, , pemFile, jwkFile] = argv;

  if (!pemFile) {
    console.error(
      "Usage: pem-to-jwk <path/to/private.pem> [<path/to/private.jwk>]"
    );
    process.exit(1);
  }

  if (!jwkFile) {
    const parsedPath = path.parse(pemFile);
    jwkFile = path.join(parsedPath.dir, `${parsedPath.name}.jwk`);
  }

  // Read the PEM private key file
  const pem = await readFile(pemFile, "utf-8");

  // Convert the PEM to a buffer
  const keyData = pemToBuffer(pem);

  // Convert the buffer to a JWK
  const jsonWebKey = await bufferToJsonWebKey(keyData);

  // Mark the JWK as used for signing
  jsonWebKey.use = "sig";

  // Write the JWK to a file
  await writeFile(jwkFile, JSON.stringify(jsonWebKey, null, 2));

  console.log(`Wrote ${jwkFile}`);
}

pemToJwk(process.argv);
