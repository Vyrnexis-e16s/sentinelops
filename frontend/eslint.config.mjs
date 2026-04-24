import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";

/** @see https://nextjs.org/docs/app/api-reference/config/eslint */
export default [
  ...coreWebVitals,
  ...typescript,
  { ignores: [".next/**", "out/**", "node_modules/**", "build/**"] }
];
