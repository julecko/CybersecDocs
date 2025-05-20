# Tmux Commands Cheat Sheet

**Tmux** (terminal multiplexer) allows you to create, manage, and navigate multiple terminal sessions. Below are common commands for working with tmux. The default prefix is `Ctrl-b`. Press the prefix before any command.

## Starting tmux
- Start a new tmux session:  
  ```bash
  tmux
  ```
- Start a named session:  
  ```bash
  tmux new -s <session-name>
  ```
- List all tmux sessions:  
  ```bash
  tmux list-sessions
  ```
- Attach to an existing session:  
  ```bash
  tmux attach -t <session-name>
  ```
- Detach from a session:  
  `Ctrl-b d`

## Managing Sessions
- List all sessions:  
  `Ctrl-b s`
- Switch to another session:  
  `Ctrl-b s` then select session
- Kill a session:  
  ```bash
  tmux kill-session -t <session-name>
  ```
- Kill all sessions:  
  ```bash
  tmux kill-server
  ```

## Working with Windows
- Create a new window:  
  `Ctrl-b c`
- Switch to next window:  
  `Ctrl-b n`
- Switch to previous window:  
  `Ctrl-b p`
- Select window by number:  
  `Ctrl-b <number>`
- Rename current window:  
  `Ctrl-b ,`
- Close current window:  
  `Ctrl-b &`

## Working with Panes
- Split pane vertically:  
  `Ctrl-b %`
- Split pane horizontally:  
  `Ctrl-b "`
- Switch between panes:  
  `Ctrl-b <arrow-key>`
- Move to next pane:  
  `Ctrl-b o`
- Resize pane (left/right/up/down):  
  `Ctrl-b Ctrl-<arrow-key>`
- Close current pane:  
  `Ctrl-b x`
- Toggle pane zoom (full-screen):  
  `Ctrl-b z`

## Copy Mode
- Enter copy mode:  
  `Ctrl-b [`
- Move cursor: Use arrow keys or `h`, `j`, `k`, `l` (Vim-style)
- Start selection:  
  `Space`
- Copy selection:  
  `Enter`
- Paste copied text:  
  `Ctrl-b ]`

## Miscellaneous
- Reload tmux configuration:  
  `Ctrl-b :source-file ~/.tmux.conf`
- Show command prompt:  
  `Ctrl-b :`
- Show all key bindings:  
  `Ctrl-b ?`
- Kill current session and switch to another:  
  `Ctrl-b )`

## Configuration
- Edit tmux configuration file:  
  ```bash
  nano ~/.tmux.conf
  ```
- Example: Change prefix to `Ctrl-a`:  
  ```bash
  set -g prefix Ctrl-a
  unbind Ctrl-b
  bind Ctrl-a send-prefix
  ```

## Tips
- Use `tmux list-commands` to see all available commands.
- Customize `~/.tmux.conf` for key bindings and settings.
- Detach and reattach sessions to persist work across terminal restarts.