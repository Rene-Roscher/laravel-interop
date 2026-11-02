<?php

declare(strict_types=1);

// Prints, as JSON on stdout, the tokens PHP issues for the end-to-end matrix, in the shape the
// other implementations print theirs (see e2e/run.sh):
//
//   verdicts: every document of fixtures/envelope-vectors.json, encrypted here
//   sealed:   tokens made by Envelope::seal for each of the vector file's seal cases

require is_file(__DIR__.'/../vendor/autoload.php') ? __DIR__.'/../vendor/autoload.php' : __DIR__.'/../../../autoload.php';

use Illuminate\Encryption\Encrypter;
use ReneRoscher\Interop\Envelope;
use ReneRoscher\Interop\Expiry;

$fixtures = json_decode((string) file_get_contents(__DIR__.'/../fixtures/envelope-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
$key = base64_decode($fixtures['key_b64']);
$encrypterFor = fn (string $cipher): Encrypter => new Encrypter(substr($key, 0, str_contains($cipher, '128') ? 16 : 32), $cipher);

$verdicts = [];
foreach ($fixtures['vectors'] as $vector) {
    if (! isset($vector['plaintext_b64']) || $vector['key'] !== 'current' || $vector['expect'] === 'decrypt_error') {
        continue;
    }
    $vector['token'] = $encrypterFor($vector['cipher'])->encryptString(base64_decode($vector['plaintext_b64']));
    $verdicts[] = $vector;
}

$sealed = [];
foreach (['aes-256-cbc', 'aes-128-gcm'] as $cipher) {
    foreach ($fixtures['seal_cases'] as $case) {
        $envelope = new Envelope($encrypterFor($cipher), static fn (): int => $case['now']);
        $expiry = match (true) {
            isset($case['expiry']['in']) => Expiry::in($case['expiry']['in']),
            isset($case['expiry']['at']) => Expiry::at($case['expiry']['at']),
            default => Expiry::never(),
        };
        $sealed[] = [
            'cipher' => $cipher,
            'name' => $case['name'],
            'token' => $envelope->seal($case['scope'], $case['data'], $expiry, $case['not_before'] ?? null),
            'case' => $case,
        ];
    }
}

echo json_encode(['key_b64' => $fixtures['key_b64'], 'verdicts' => $verdicts, 'sealed' => $sealed], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION), "\n";
