# portfolio-ssh

A custom SSH server written in Go that serves a terminal-based portfolio application built with Python and Textual.

Users can connect via SSH, complete a cryptographic challenge to prove ownership of their SSH key, and then interact with the portfolio directly in their terminal.

---

## ✨ Overview

This project is part of a multi-layered portfolio system:

- **portfolio-tui** → Terminal UI built with Python + Textual  
- **portfolio-ssh** → Custom SSH server (this repo)  
- **portfolio-web** → Web version (planned)

The goal is to create a unique, developer-focused portfolio experience that can be accessed via:

```bash
ssh guest@mydomain.com
``` 

### Flow
1. User connects via SSH
2. Server prompts user to paste their public key
3. Server generates a short-lived challenge
4. User signs the challenge locally using their private key
5. Server verifies the signature
6. If valid, the portfolio TUI is launched in the SSH session

This ensures that users prove ownership of their SSH key without requiring a web form or pre-registration.

### Running Locally
1. Start the SSH server:
```go run ./cmd/server```

    You should see:

    ```SSH server listening on :2222```

2. Connect via SSH
    In another terminal, run:
    ```ssh localhost -p 2222```

3. Complete the challenge
- Paste your public SSH key 
    ```cat ~/.ssh/id_ed25519.pub```
- Sign the challenge in a third terminal:
```
printf '%s' "<challenge>" | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file
```
- Paste the full signature block (including `-----BEGIN SSH SIGNATURE-----` and `-----END SSH SIGNATURE-----`) back into the SSH session

4. Launch the portfolio app
    If verification succeeds, the terminal portfolio will launch.   

#### Quick Notes
- This server requires proof-of-possession of an SSH private key.
- No passwords or web-based onboarding are used
- Challenges are short-lived and single-use
- Rate limiting: max 5 connections per IP per minute
- Session timeout: 5 minutes to complete authentication
- connection limits