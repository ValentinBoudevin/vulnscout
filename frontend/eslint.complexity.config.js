// Isolated ESLint config for complexity / function-length reporting only.
// Kept separate from eslint.config.js so the main lint gate (which runs with
// --max-warnings 0) is not affected. Run via `make -C tests test_complexity`.
import tsParser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  {
    ignores: [
      "dist",
      "tests/**",
      "__tests__/**",
      "**/*.test.ts",
      "**/*.test.tsx",
    ],
  },
  {
    files: ["src/**/*.ts", "src/**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    // Don't flag the source's react-hooks disable directives as unused just
    // because this report-only config keeps those rules off.
    linterOptions: {
      reportUnusedDisableDirectives: "off",
    },
    // Register react-hooks so inline `eslint-disable react-hooks/*` directives
    // in the source resolve instead of raising "rule not found" errors. The
    // rules themselves are off; this config only reports complexity/length.
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      "react-hooks/exhaustive-deps": "off",
      "react-hooks/rules-of-hooks": "off",
      // Cyclomatic complexity per function (independent decision paths).
      complexity: ["warn", 15],
      // Raw function length, ignoring blank lines and comments.
      "max-lines-per-function": [
        "warn",
        { max: 150, skipBlankLines: true, skipComments: true },
      ],
      // Deep nesting is a strong readability signal.
      "max-depth": ["warn", 4],
    },
  },
];

