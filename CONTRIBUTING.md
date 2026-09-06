# Contributing to open-engine

First off, thank you for considering contributing! We welcome all contributions, from bug reports and documentation updates to new features and performance improvements.

## Getting Started

1. **Fork the repository** on GitHub and clone it locally.
2. **Ensure you have Rust installed.** We recommend using [rustup](https://rustup.rs/).
3. **Install Redis** (or use Docker) since the `queue` and other components rely on it.
   ```bash
   docker run --rm -p 6379:6379 redis:7-alpine
   ```

## Development Workflow

1. **Create a branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes.** Keep your commits small and focused.

3. **Format your code** using `rustfmt`:
   ```bash
   cargo fmt
   ```

4. **Lint your code** using `clippy`. Ensure there are no warnings:
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```

5. **Run the tests** to ensure everything is still working properly:
   ```bash
   cargo test
   ```
   *(Note: Remember to have Redis running locally when testing the queue module!)*

6. **Commit your changes.** Please write clear, concise commit messages. 

## Submitting a Pull Request

- Push your branch to your fork.
- Open a Pull Request against the `main` branch of this repository.
- Describe the changes you've made, the reasoning behind them, and any related issues.
- Wait for a review!

## Code of Conduct

Please be respectful, constructive, and considerate of others when participating in this project.

Thank you for contributing!
