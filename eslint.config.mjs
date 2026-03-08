/**
 * ESLint flat config with security-focused linting rules.
 *
 * Uses eslint-plugin-security to detect common security anti-patterns
 * such as eval(), non-literal RegExp, non-literal require(), etc.
 *
 * @see CICD-009
 */
import pluginSecurity from "eslint-plugin-security";

export default [
  // Security plugin recommended config
  pluginSecurity.configs.recommended,
  {
    files: ["src/**/*.ts", "src/**/*.js"],
    plugins: {
      security: pluginSecurity,
    },
    rules: {
      // All security plugin rules are included via recommended config above.
      // Override specific rules here if needed:
      // "security/detect-object-injection": "off",  // too many false positives
    },
  },
  {
    // Ignore build output and test files for security linting
    ignores: ["build/**", "coverage/**", "node_modules/**"],
  },
];
