# @vert/auth

Authentication library for Bun — inspired by Devise. Password hashing with Argon2id (native `Bun.password`), sessions, confirmation, recovery, lockout, tracking, and OmniAuth-like social providers.

## Installation

```bash
bun add @vert/auth
```

## Modules

| Module | Description |
|--------|-------------|
| Authenticatable | Password hashing (Argon2id) and credential validation |
| Registerable | User registration, profile update, account deletion |
| Confirmable | Email confirmation with secure tokens |
| Recoverable | Password reset with expirable tokens |
| Rememberable | "Remember me" cookie sessions |
| Trackable | Sign-in count, timestamps, IP tracking |
| Timeoutable | Session timeout by inactivity |
| Lockable | Account lock after failed attempts |
| Validatable | Email and password validation schemas (Zod) |
| OmniAuth | Social login (Google, GitHub, Apple) |

## License

MIT
