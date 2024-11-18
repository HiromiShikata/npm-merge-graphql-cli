# npm-merge-graphql-cli

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/HiromiShikata/npm-merge-graphql-cli/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/HiromiShikata/npm-merge-graphql-cli/tree/main)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)
[![semantic-release: angular](https://img.shields.io/badge/semantic--release-angular-e10079?logo=semantic-release)](https://github.com/semantic-release/semantic-release)


Merge GraphQL Definitions

This library allows you to merge multiple GraphQL schema definitions, both auto-generated and manually defined. It was created to address the need to utilize both automatically generated GraphQL types as well as custom, hand-crafted definitions within the same application.

The auto-generated portions are abstracted out into a separate library component, which improves the overall reusability and flexibility of the solution. This allows you to combine the efficiency of automated GraphQL type generation with the control and customization enabled by manual schema definitions.

Key features:

- Seamlessly merge auto-generated and manually defined GraphQL types
- Maintain separation of concerns by isolating auto-generation logic
- Improve reusability by packaging auto-generated components distinctly
- Unified API for managing the combined GraphQL schema
- TypeScript support for type-safe interactions

Whether your project requires extensive custom GraphQL modeling or benefits from automated type generation, this library provides a streamlined approach to consolidating your diverse GraphQL definitions into a cohesive schema.
