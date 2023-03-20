module.exports = {
  "env": {
    // "browser": true,
    "es2021": true,
    "node": true,
  },
  "extends": "eslint:recommended",
  "overrides": [
  ],
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module"
  },
  "plugins": [

  ],
  "rules": {
    "no-unused-vars": ["warn", {
      "argsIgnorePattern": "^(_|next$)",
      "varsIgnorePattern": "^(_|next$)",
      "caughtErrorsIgnorePattern": "^(_|next$)"
    }]
  },
  "globals": {
    "console": true
  }
}
