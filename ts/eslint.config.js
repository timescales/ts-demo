// Flat config for the SDK and the web app.
import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const kitRuntime = {
  name: '@solana/kit',
  message:
    'Only solana/tx.ts, solana/rpc.ts and wallet/standard.ts import the @solana/kit runtime; use `import type` elsewhere.',
  allowTypeImports: true,
};

const restrictedSyntax = [
  {
    selector: "MemberExpression[object.name='ed25519'][property.name='verify']",
    message:
      "noble's ed25519.verify accepts signatures that dalek rejects; use verifyStrict from core/crypto/ed25519.ts.",
  },
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'Raw HTML is banned (CSP with Trusted Types, ).',
  },
];

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/dist-test/**',
      '**/test-results/**',
      '**/playwright-report/**',
      '**/blob-report/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
      ],
      '@typescript-eslint/no-restricted-imports': ['error', { paths: [kitRuntime] }],
      'no-restricted-syntax': ['error', ...restrictedSyntax],
    },
  },
  {
    files: [
      'packages/sdk/src/solana/tx.ts',
      'packages/sdk/src/solana/rpc.ts',
      'packages/sdk/src/wallet/standard.ts',
    ],
    rules: {
      '@typescript-eslint/no-restricted-imports': 'off',
    },
  },
  {
    files: ['packages/sdk/src/core/crypto/ed25519.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...restrictedSyntax.slice(1)],
    },
  },
  {
    files: ['apps/web/src/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          paths: [
            kitRuntime,
            {
              name: '@timescales/sdk/testing',
              message: 'Test doubles never ship in the app.',
            },
          ],
          patterns: [
            {
              group: ['@timescales/sdk/testing/*', '**/packages/sdk/src/testing/**'],
              message: 'Test doubles never ship in the app.',
            },
          ],
        },
      ],
    },
  },
);
