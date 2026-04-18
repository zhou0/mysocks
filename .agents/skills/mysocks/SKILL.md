```markdown
# mysocks Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the development conventions and workflows used in the `mysocks` TypeScript codebase. You'll learn about file naming, import/export styles, commit message patterns, and how to write and run tests. This guide is designed to help you contribute code that fits seamlessly into the project.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `myUtility.ts`, `userService.ts`

### Imports
- Use **relative imports** for referencing modules within the project.
  - Example:
    ```typescript
    import { myFunction } from './myUtility';
    ```

### Exports
- Use **named exports** for all modules.
  - Example:
    ```typescript
    // myUtility.ts
    export function myFunction() { ... }
    ```

### Commit Messages
- Commit messages are **freeform** (no enforced prefix).
- Average commit message length: ~49 characters.
- Example:
  ```
  Fix bug in user authentication logic
  ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add new functionality.
**Command:** `/add-module`

1. Create a new file using camelCase naming (e.g., `newFeature.ts`).
2. Implement your logic using named exports.
3. Use relative imports to include dependencies.
4. Write a corresponding test file named `newFeature.test.ts`.
5. Commit your changes with a clear, descriptive message.

### Writing and Running Tests
**Trigger:** When you add or update code and need to ensure correctness.
**Command:** `/run-tests`

1. Create or update a test file matching the pattern `*.test.ts`.
2. Write tests for your exported functions.
3. Use the project's test runner (framework is unknown; check project docs or package.json).
4. Run tests and ensure all pass before committing.

### Refactoring Code
**Trigger:** When improving or reorganizing existing code.
**Command:** `/refactor`

1. Identify code to refactor.
2. Rename files using camelCase if needed.
3. Update all relative imports accordingly.
4. Ensure all exports remain named.
5. Update or add tests as necessary.
6. Commit with a message describing the refactor.

## Testing Patterns

- Test files follow the pattern: `*.test.ts`
- Place tests alongside or near the modules they test.
- Testing framework is not specified; refer to project documentation or `package.json` for details.
- Example test file:
  ```typescript
  // myUtility.test.ts
  import { myFunction } from './myUtility';

  test('myFunction returns expected result', () => {
    expect(myFunction()).toBe('expected');
  });
  ```

## Commands
| Command      | Purpose                                   |
|--------------|-------------------------------------------|
| /add-module  | Scaffold a new module with tests          |
| /run-tests   | Run all test files in the codebase        |
| /refactor    | Refactor code while following conventions |
```
