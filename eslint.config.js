// ESLint 9 flat config.
//
// `pnpm lint` has been failing with "couldn't find an eslint.config file" since
// the eslint@^9 bump: the migration installed the new major and never added the
// config it requires. CI never noticed because CI never got as far as linting,
// `npm ci` failed first against a repo that has only a pnpm lockfile.
//
// Deliberately narrow. This restores a lint step that runs and can fail; it is
// not the place to introduce a rule set nobody has reviewed, which would either
// bury the build in pre-existing violations or get switched off.
import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**', '*.config.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Tests assert on loosely-typed JSON fixtures; `any` there is honest.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
)
