import { setGlobalOptions } from "firebase-functions";
import { onRequest } from "firebase-functions/https";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";

// Global options
setGlobalOptions({ maxInstances: 10 });

// Initialize Firebase Admin SDK
admin.initializeApp();

// Example: Test endpoint
export const helloWorld = onRequest((req, res) => {
  logger.info("Hello logs!", { structuredData: true });
  res.send("Hello from Firebase Functions with TypeScript!");
});

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
