import type { ActionArgs } from "@remix-run/node";
import { redirect } from "@remix-run/node";

import { signOut } from "~/session.server";

export async function action({ request }: ActionArgs) {
  return signOut(request);
}

export async function loader() {
  return redirect("/");
}
