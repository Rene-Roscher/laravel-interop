# laravel-interop

Expiring, scoped payloads on top of Laravel's encrypter. An **Interop Envelope** is a small JSON
document with a scope, timestamps and data, encrypted with `Crypt::encryptString()`. Because the
encryption authenticates it, neither the scope nor the timestamps can be changed without the app
key, and any service that shares the key can open it:

| Language | Package |
|---|---|
| PHP / Laravel | this package |
| Rust | [laravel-rust-encryption](https://github.com/Rene-Roscher/laravel-rust-encryption) (`envelope` module) |
| Go | [laravel-go-encryption](https://github.com/Rene-Roscher/laravel-go-encryption) (`Seal` / `Open`) |
| Node.js | [laravel-node-encryption](https://github.com/Rene-Roscher/laravel-node-encryption) (`Envelope`) |

Use it for anything that should stop working after a while or outside of one purpose: password
reset and invite links, download links, API tokens between services, short-lived messages.

## Install

```sh
composer require rene-roscher/laravel-interop
```

The service provider is auto-discovered and binds `Envelope` to the application's encrypter.

## Usage

```php
use ReneRoscher\Interop\Envelope;
use ReneRoscher\Interop\EnvelopeException;
use ReneRoscher\Interop\Expiry;

$envelope = app(Envelope::class);

// Seal: what it is for, what it carries, when it stops working.
$token = $envelope->seal('password-reset', ['user' => 7], Expiry::in(3600));

// Open: say what you expect it to be for.
try {
    $opened = $envelope->open($token, 'password-reset');
    $opened->data;       // ['user' => 7]
    $opened->expiresAt;  // Unix timestamp, or null
} catch (EnvelopeException $e) {
    $e->kind();          // 'expired', 'scope_mismatch', ...
}
```

`Expiry::in($seconds)`, `Expiry::at($timestamp)` or `Expiry::never()` has to be chosen on every
`seal()`, so a token never lives forever by accident. `seal()` also takes `notBefore:` (a Unix
timestamp), and `open()` takes `leeway:` (seconds of clock difference to tolerate) and `now:` (to
override the clock in tests).

A payload that does not decrypt (wrong key, tampering) throws Laravel's `DecryptException`, before the
envelope is looked at. The encrypter's previous keys (`APP_PREVIOUS_KEYS`) apply.

## The format (v1)

The plaintext that goes through `encryptString()`:

```json
{"typ":"env","v":1,"iat":1700000000,"nbf":1700000030,"exp":1700003600,"scope":"password-reset","data":{"user":7}}
```

| Field | Required | Meaning |
|---|---|---|
| `typ` | yes | Always `"env"`. Keeps a session or cookie payload from being taken for an envelope. |
| `v` | yes | Format version, `1`. |
| `iat` | yes | When it was sealed, Unix seconds (UTC). Informational. |
| `nbf` | no | Not valid before this time. |
| `exp` | no | Not valid from this time on. No `exp` means it never expires. |
| `scope` | yes | What it may be used for: a non-empty string, compared exactly (case-sensitive, no prefixes). |
| `data` | yes | Any JSON value, `null` included. Keep nesting below 64 levels. |

Timestamps are JSON numbers without a fractional part. Other fields are ignored, so a later
version can add some; a change that readers must not ignore raises `v`.

**Verdicts.** Opening decides in this order, and the first failure wins:

1. `invalid`: not a JSON object, `typ` is not `"env"`, or a field has the wrong type or is missing
   (the version is read first, so a document with another `v` is `unsupported_version` before
   anything else is judged).
2. `unsupported_version`: `v` is not `1`.
3. `scope_mismatch`: `scope` is not the expected one.
4. `not_yet_valid`: `now < nbf - leeway`.
5. `expired`: `now >= exp + leeway`.

So a token is valid for `nbf - leeway <= now < exp + leeway`. A failure to decrypt is separate and
comes first (`decrypt_error` in the shared test vectors).

## Tests

```sh
composer install
vendor/bin/phpunit
php bin/generate-vectors.php   # regenerate fixtures/envelope-vectors.json
```

`fixtures/envelope-vectors.json` holds documents of every shape above, encrypted by the real Laravel
encrypter (two ciphers, with the verdict every implementation has to reach). The Rust, Go and
Node.js packages open the same tokens, and re-encrypt the same documents themselves for
`bin/verify-tokens.php` to judge. CI runs the tests for Laravel 10 to 13.

`e2e/run.sh` goes further: PHP, Rust, Go and Node.js each issue tokens (the vector documents and
tokens they seal themselves), and each of the four judges the tokens of each of the four, 16
combinations with the same 182 tokens. It expects the three packages next to this one
(`e2e/run.sh [directory]`), builds them and prints one line per combination. It also fails when a
package's copy of the vectors has drifted from this one. CI runs it for Laravel 10 to 13, and weekly.

## License

MIT © René Roscher
