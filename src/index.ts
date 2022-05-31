#!/usr/bin/env node

import { createPrivateKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

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
  const unwrapped = pem.replace(/-{5}(BEGIN|END).*-{5}/g, "");
  const keyData = Buffer.from(unwrapped, "base64");

  // Convert the buffer to a JWK
  const jsonWebKey = await createPrivateKey({
    key: keyData,
    type: "pkcs8",
    format: "der",
  }).export({
    format: "jwk",
  });

  // Write the JWK to a file
  await writeFile(jwkFile, JSON.stringify(jsonWebKey, null, 2));

  console.log(`Wrote ${jwkFile}`);
}

pemToJwk(process.argv);
