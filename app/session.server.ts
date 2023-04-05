import { createCookieSessionStorage, redirect } from "@remix-run/node";
import invariant from "tiny-invariant";
import {
  getSessionToken,
  signOutFirebase,
  adminAuth,
  useUser,
} from "./firebase.server";

invariant(process.env.SESSION_SECRET, "SESSION_SECRET must be set");

export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "__session",
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secrets: [process.env.SESSION_SECRET],
    maxAge: 60 * 60 * 24 * 7,
    secure: process.env.NODE_ENV === "production",
  },
});

const USER_SESSION_KEY = "userId";
const FIREBASE_TOKEN_KEY = "fbtoken";

export async function createUserSession({
  idToken,
  redirectTo,
  remember,
}: {
  request: Request;
  idToken: string;
  remember: boolean;
  redirectTo: string;
}) {
  const session = await sessionStorage.getSession();
  const token = await getSessionToken(idToken);
  const user = await useUser();

  session.set(USER_SESSION_KEY, user);
  session.set(FIREBASE_TOKEN_KEY, token);

  return redirect(redirectTo, {
    headers: {
      "Set-Cookie": await sessionStorage.commitSession(session, {
        maxAge: remember
          ? 60 * 60 * 24 * 7 // 7 days
          : undefined,
      }),
    },
  });
}

export async function getUserSession(request: Request) {
  const cookieSession = await sessionStorage.getSession(
    request.headers.get("Cookie")
  );
  const token = cookieSession.get(FIREBASE_TOKEN_KEY);
  if (!token) return null;

  try {
    const tokenUser = await adminAuth.verifySessionCookie(token, true);
    return tokenUser;
  } catch (error) {
    return null;
  }
}

async function destroySession(request: Request) {
  const session = await sessionStorage.getSession(
    request.headers.get("Cookie")
  );
  const newCookie = await sessionStorage.destroySession(session);

  return redirect("/", { headers: { "Set-Cookie": newCookie } });
}

export async function signOut(request: Request) {
  await signOutFirebase();
  return await destroySession(request);
}

export async function optionalUser(request: Request) {
  return await getUserSession(request);
}

export async function requireUser(request: Request) {
  const session = await getUserSession(request);
  if (!session) {
    throw redirect("/login");
  }
  return session;
}
