<?php

declare(strict_types=1);

// Reads the JSON that an implementation prints on STDIN and judges its tokens with this package:
//
//   {"key_b64": "...", "verdicts": [{cipher, name, token, scope, now, leeway, expect, data, iat, nbf, exp}],
//    "sealed": [{cipher, name, token, case: {scope, data, expiry, not_before, now}}]}
//
// "verdicts" are re-encrypted vectors: PHP has to reach the verdict the vector names.
// "sealed" are tokens the implementation sealed itself: PHP has to open them and read back
// exactly what was sealed. Exits non-zero on any difference.

// Works from this repository and from the vendor directory of a project that requires it.
require is_file(__DIR__.'/../vendor/autoload.php') ? __DIR__.'/../vendor/autoload.php' : __DIR__.'/../../../autoload.php';

use Illuminate\Encryption\Encrypter;
use ReneRoscher\Interop\Envelope;
use ReneRoscher\Interop\EnvelopeException;

$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$rawKey = base64_decode($input['key_b64']);

$failures = 0;
$fail = function (string $message) use (&$failures): void {
    $failures++;
    if ($failures <= 20) {
        fwrite(STDERR, "FAIL $message\n");
    }
};

$encrypterFor = fn (string $cipher): Encrypter => new Encrypter(substr($rawKey, 0, str_contains($cipher, '128') ? 16 : 32), $cipher);

foreach ($input['verdicts'] ?? [] as $v) {
    $envelope = new Envelope($encrypterFor($v['cipher']));
    try {
        $opened = $envelope->open($v['token'], $v['scope'], $v['leeway'], $v['now']);
        $kind = 'ok';
    } catch (EnvelopeException $e) {
        $kind = $e->kind();
    } catch (\Illuminate\Contracts\Encryption\DecryptException) {
        $kind = 'decrypt_error';
    }

    if ($kind !== $v['expect']) {
        $fail("[{$v['cipher']}/{$v['name']}] expected {$v['expect']}, PHP says $kind");
        continue;
    }
    if ($kind === 'ok' && ($opened->issuedAt !== $v['iat'] || $opened->notBefore !== ($v['nbf'] ?? null) || $opened->expiresAt !== ($v['exp'] ?? null)
        || json_encode($opened->data) !== json_encode($v['data']))) {
        $fail("[{$v['cipher']}/{$v['name']}] opened with other fields: ".json_encode($opened));
    }
}

foreach ($input['sealed'] ?? [] as $s) {
    $case = $s['case'];
    $envelope = new Envelope($encrypterFor($s['cipher']));
    try {
        // Open it once it is valid, so the check is about the fields and not the clock.
        $opened = $envelope->open($s['token'], $case['scope'], 0, max($case['now'] + 1, $case['not_before'] ?? 0));
    } catch (\Throwable $e) {
        $fail("[{$s['cipher']}/{$s['name']}] sealed token not opened: ".get_class($e).': '.$e->getMessage());
        continue;
    }

    $expectedExp = match (true) {
        isset($case['expiry']['in']) => $case['now'] + $case['expiry']['in'],
        isset($case['expiry']['at']) => $case['expiry']['at'],
        default => null,
    };
    if ($opened->issuedAt !== $case['now'] || $opened->expiresAt !== $expectedExp || $opened->notBefore !== ($case['not_before'] ?? null)
        || json_encode($opened->data) !== json_encode($case['data'])) {
        $fail("[{$s['cipher']}/{$s['name']}] opened with other fields: ".json_encode($opened).' vs '.json_encode($case));
    }
}

$total = count($input['verdicts'] ?? []) + count($input['sealed'] ?? []);
if ($failures > 0) {
    fwrite(STDERR, "$failures/$total token(s) were judged differently\n");
    exit(1);
}
fwrite(STDERR, "PHP agrees on all $total tokens\n");
