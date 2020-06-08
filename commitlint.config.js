module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'subject-case': [2, 'never', ['start-case', 'pascal-case', 'upper-case']],
    'scope-case': [2, 'always', ['pascal-case', 'lower-case', 'camel-case']],
  },
}
