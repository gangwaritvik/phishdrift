import { readFileSync } from "node:fs";

const dist = new URL("../dist/", import.meta.url);
export const readDist = (path) => JSON.parse(readFileSync(new URL(path, dist), "utf8"));
export const psl = () => readDist("data/psl_icann.json");
