# Git Usage Guide

This guide covers the essentials of using Git, a distributed version control system, including common commands, options, and best practices for managing repositories.

## What is Git?

Git is a distributed version control system used to track changes in source code during software development. It allows multiple developers to collaborate, manage versions, and maintain a history of changes.

## Basic Git Setup

Before using Git, configure your user information:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

Optionally, set your preferred editor:

```bash
git config --global core.editor vim
```

## Common Git Commands and Options

### Initializing a Repository

- **Initialize a new Git repository**:
  ```bash
  git init
  ```
  Creates a `.git` directory in the current folder.

- **Clone an existing repository**:
  ```bash
  git clone <repository-url>
  ```
  Supports HTTPS or SSH URLs.

### Working with Changes

- **Check repository status**:
  ```bash
  git status
  ```
  Shows modified, staged, and untracked files.

- **Add files to staging**:
  ```bash
  git add <file>
  ```
  - Add all files: `git add .`

- **Commit changes**:
  ```bash
  git commit -m "Commit message"
  ```
  - `-a`: Automatically stages modified and deleted files:
    ```bash
    git commit -a -m "Commit message"
    ```

- **View commit history**:
  ```bash
  git log
  ```
  - `--oneline`: Compact view:
    ```bash
    git log --oneline
    ```
  - `--graph`: Visualize branches:
    ```bash
    git log --graph --all
    ```

### Branching and Merging

- **List branches**:
  ```bash
  git branch
  ```
  - `-a`: List all branches (local and remote):
    ```bash
    git branch -a
    ```

- **Create a new branch**:
  ```bash
  git branch <branch-name>
  ```

- **Switch to a branch**:
  ```bash
  git checkout <branch-name>
  ```
  - Create and switch to a new branch:
    ```bash
    git checkout -b <branch-name>
    ```

- **Merge a branch**:
  ```bash
  git merge <branch-name>
  ```
  Merges `<branch-name>` into the current branch.

- **Delete a branch**:
  ```bash
  git branch -d <branch-name>
  ```
  - Force delete (unmerged branch): `git branch -D <branch-name>`

### Remote Repositories

- **Add a remote repository**:
  ```bash
  git remote add origin <repository-url>
  ```

- **Push changes to a remote**:
  ```bash
  git push origin <branch-name>
  ```
  - `-u`: Set upstream for future pushes:
    ```bash
    git push -u origin <branch-name>
    ```
  - `--force`: Overwrite remote branch (use with caution):
    ```bash
    git push --force
    ```

- **Fetch changes from a remote**:
  ```bash
  git fetch origin
  ```

- **Pull changes from a remote**:
  ```bash
  git pull origin <branch-name>
  ```
  Combines `git fetch` and `git merge`.

### Undoing Changes

- **Discard changes in working directory**:
  ```bash
  git restore <file>
  ```
  - Discard all changes: `git restore .`

- **Unstage files**:
  ```bash
  git restore --staged <file>
  ```

- **Amend the last commit**:
  ```bash
  git commit --amend
  ```
  Updates message or includes new changes.

- **Revert a commit**:
  ```bash
  git revert <commit-hash>
  ```
  Creates a new commit that undoes the specified commit.

- **Reset to a previous state**:
  ```bash
  git reset <commit-hash>
  ```
  - `--soft`: Keeps changes in working directory and staging.
  - `--hard`: Discards all changes after the specified commit.

### Stashing Changes

- **Save changes temporarily**:
  ```bash
  git stash
  ```
  - Include a message: `git stash push -m "Stash message"`

- **List stashes**:
  ```bash
  git stash list
  ```

- **Apply a stash**:
  ```bash
  git stash apply
  ```
  - Apply specific stash: `git stash apply stash@{n}`

- **Delete a stash**:
  ```bash
  git stash drop stash@{n}
  ```
  - Clear all stashes: `git stash clear`

## Using SSH with Git

To use SSH for Git operations (e.g., with GitHub, GitLab):

1. **Generate an SSH key** (if not already done):
   ```bash
   ssh-keygen -t rsa -b 4096 -C "your.email@example.com" -f ~/.ssh/id_rsa
   ```

2. **Add the public key to the Git server**:
   Copy the public key to the Git server’s SSH key settings (e.g., GitHub’s "Settings > SSH and GPG keys").

3. **Add the private key to SSH agent**:
   ```bash
   ssh-add ~/.ssh/id_rsa
   ```

4. **Configure Git to use SSH**:
   Set SSH URL for the repository:
   ```bash
   git remote set-url origin ssh://git@<server>/<username>/<repo>.git
   ```

5. **Test the connection**:
   ```bash
   ssh -T git@<server>
   ```

## Git Configuration File

Store Git settings in `~/.gitconfig` or `.git/config` (repository-specific):

```bash
[core]
    editor = vim
    autocrlf = input
[alias]
    st = status
    ci = commit
    co = checkout
    br = branch
```

- Set aliases for convenience:
  ```bash
  git config --global alias.st status
  ```

## Best Practices

- Write clear commit messages with descriptive details.
- Commit often, but group related changes into meaningful commits.
- Use branches for features to keep the main branch stable.
- Pull changes before pushing to avoid merge conflicts.
- Securely store SSH keys and never share private keys.
- Review changes with `git diff` before committing:
  ```bash
  git diff
  ```

## Troubleshooting

- **Authentication issues**:
  - Verify the SSH key is added to the SSH agent.
  - Test SSH connection: `ssh -vT git@<server>`.
- **Merge conflicts**:
  - Resolve conflicts manually in affected files, then:
    ```bash
    git add <file>
    git commit
    ```
- **Check Git logs**:
  - Use `git log --oneline` to find problematic commits.