<?php

declare(strict_types=1);

// Reads tokens as the implementations print them (see bin/emit-tokens.php) on STDIN and prints,
// as JSON on stdout, what this package makes of each one. e2e/compare.php holds the result
// against what the tokens should give.

require is_file(__DIR__.'/../vendor/autoload.php') ? __DIR__.'/../vendor/autoload.php' : __DIR__.'/../../../autoload.php';

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter;
use ReneRoscher\Interop\Envelope;
use ReneRoscher\Interop\EnvelopeException;

$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$key = base64_decode($input['key_b64']);

$judge = function (string $cipher, string $token, string $scope, int $leeway, int $now) use ($key): array {
    $envelope = new Envelope(new Encrypter(substr($key, 0, str_contains($cipher, '128') ? 16 : 32), $cipher));
    try {
        $opened = $envelope->open($token, $scope, $leeway, $now);

        return ['verdict' => 'ok', 'iat' => $opened->issuedAt, 'nbf' => $opened->notBefore, 'exp' => $opened->expiresAt, 'data' => $opened->data];
    } catch (EnvelopeException $e) {
        return ['verdict' => $e->kind()];
    } catch (DecryptException) {
        return ['verdict' => 'decrypt_error'];
    }
};

$results = ['verdicts' => [], 'sealed' => []];
foreach ($input['verdicts'] as $v) {
    $results['verdicts'][] = $judge($v['cipher'], $v['token'], $v['scope'], $v['leeway'], $v['now']);
}
foreach ($input['sealed'] as $s) {
    // Open it once it is valid, so the check is about the fields and not the clock.
    $results['sealed'][] = $judge($s['cipher'], $s['token'], $s['case']['scope'], 0, max($s['case']['now'] + 1, $s['case']['not_before'] ?? 0));
}

echo json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION), "\n";
