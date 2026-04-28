import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";

/** @see https://nextjs.org/docs/app/api-reference/config/eslint */
const eslintConfig = [
  ...coreWebVitals,
  ...typescript,
  {
    rules: {
      // Project uses Next/Image where it matters; allow plain <img> in marketing/auth pages.
      "@next/next/no-img-element": "off",
    },
  },
  { ignores: [".next/**", "out/**", "node_modules/**", "build/**"] },
];

export default eslintConfig;
