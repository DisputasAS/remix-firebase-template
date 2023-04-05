import admin from "firebase-admin";
import { initializeApp as initializeAdminApp, cert } from "firebase-admin/app";
import { FirebaseApp, initializeApp } from "firebase/app";
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  getAuth,
  signOut,
} from "firebase/auth";
import { redirect } from "react-router";

let app: FirebaseApp | undefined;

const serviceAccountPath = "myserviceaccount.json";

if (!admin.apps.length) {
  initializeAdminApp({
    credential: cert(require(serviceAccountPath)),
  });
}

const db = admin.firestore();
const adminAuth = admin.auth();

if (!app) {
  app = initializeApp({
    apiKey: process.env.FIREBASE_APIKEY,
    authDomain: process.env.FIREBASE_AUTHDOMAIN,
    projectId: process.env.FIREBASE_PROJECTID,
    storageBucket: process.env.FIREBASE_STORAGEBUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGINGSENDERID,
    appId: process.env.FIREBASE_APPID,
  });
}

async function signIn(email: string, password: string) {
  const auth = getAuth();
  return await signInWithEmailAndPassword(auth, email, password);
}

async function signUp(email: string, password: string) {
  const auth = getAuth();
  return await createUserWithEmailAndPassword(auth, email, password);
}

async function getSessionToken(idToken: string) {
  const decodedToken = await adminAuth.verifyIdToken(idToken);
  if (new Date().getTime() / 1000 - decodedToken.auth_time > 5 * 60) {
    throw new Error("Recent sign in required");
  }
  const oneWeek = 60 * 60 * 24 * 7 * 1000;
  return await adminAuth.createSessionCookie(idToken, { expiresIn: oneWeek });
}

async function signOutFirebase() {
  await signOut(getAuth());
}

export async function useUser() {
  const user = await getAuth().currentUser;
  if (!user) throw redirect("/login");
  return user;
}

export { db, signUp, getSessionToken, signOutFirebase, signIn, adminAuth };
