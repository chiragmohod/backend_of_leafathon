import { setGlobalOptions } from "firebase-functions";
import { onRequest } from "firebase-functions/https";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import fetch from "node-fetch";
import * as jwt from "jsonwebtoken";
import { importJWK, jwtVerify } from "jose";

// Global options
setGlobalOptions({ maxInstances: 10 });

// Initialize Firebase Admin SDK
admin.initializeApp();

// Example: Test endpoint

// Authentication: Verify ID Token from frontend
export const verifyToken = onRequest(async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      res.status(400).send("❌ Token missing");
      return;
    }

    const decoded = await admin.auth().verifyIdToken(token);

    res.status(200).send({
      message: "✅ Token verified",
      uid: decoded.uid,
      email: decoded.email,
    });
  } catch (error: any) {
    res.status(401).send(`❌ Invalid token: ${error.message}`);
  }
});

export const helloWorld = onRequest((req, res) => {
  logger.info("Hello logs!", { structuredData: true });
  res.send("Hello from Firebase Functions with TypeScript!");
});

// 🔹 Verify Google ID Token
export const verifyGoogleToken = onRequest(async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      res.status(400).send("❌ Token missing");
      return;
    }

    // Firebase Admin automatically verifies Google tokens
    const decoded = await admin.auth().verifyIdToken(token);

    res.status(200).send({
      message: "✅ Google token verified",
      uid: decoded.uid,
      email: decoded.email,
    });
  } catch (error: any) {
    res.status(401).send(`❌ Invalid Google token: ${error.message}`);
  }
});

// 🔹 Verify Apple ID Token
export const verifyAppleToken = onRequest(async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      res.status(400).send("❌ Token missing");
      return;
    }

    // Apple’s public keys (rotate often)
    const appleKeys = await fetch("https://appleid.apple.com/auth/keys").then(r => r.json());

    // Decode header to find correct Apple key
    const decodedHeader: any = jwt.decode(token, { complete: true })?.header;
    if (!decodedHeader) throw new Error("Invalid token header");

    const key = appleKeys.keys.find((k: any) => k.kid === decodedHeader.kid);
    if (!key) throw new Error("Apple public key not found");
    // Verify token using Apple public key
    const pubKey = await importJWK(key, "RS256");
    const { payload } = await jwtVerify(token, pubKey, {
      issuer: "https://appleid.apple.com",
    });

    res.status(200).send({
      message: "✅ Apple token verified",
      payload,
    });
  } catch (error: any) {
    res.status(401).send(`❌ Invalid Apple token: ${error.message}`);
  }
});
