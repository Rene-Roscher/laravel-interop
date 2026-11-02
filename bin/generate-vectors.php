<?php

declare(strict_types=1);

// Writes fixtures/envelope-vectors.json: envelope documents of every shape the verdict rules
// cover, encrypted by the real Laravel encrypter, with the verdict every implementation has to
// reach. The Rust, Go and Node.js packages copy this file and open each token; they also
// re-encrypt each plaintext themselves and let bin/verify-tokens.php judge those tokens.

// Works from this repository and from the vendor directory of a project that requires it.
require is_file(__DIR__.'/../vendor/autoload.php') ? __DIR__.'/../vendor/autoload.php' : __DIR__.'/../../../autoload.php';

use Illuminate\Encryption\Encrypter;

$ciphers = ['aes-256-cbc', 'aes-128-gcm'];
$keyBytes = str_repeat("\x2b", 32);
$previousKeyBytes = str_repeat("\x7a", 32);
$strangerKeyBytes = str_repeat("\x11", 32);

const NOW = 1700000100;

/** A well-formed v1 document; $overrides replace fields, null removes them. */
function doc(array $overrides = []): string
{
    $doc = [
        'typ' => 'env',
        'v' => 1,
        'iat' => 1700000000,
        'exp' => 1700003600,
        'scope' => 'password-reset',
        'data' => ['user' => 7],
    ];
    foreach ($overrides as $field => $value) {
        if ($value === null) {
            unset($doc[$field]);
        } else {
            $doc[$field] = $value;
        }
    }

    $json = json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);

    return str_replace(json_encode(JSON_NULL), 'null', $json);
}

/** Marks a field value that must be written as JSON null (a plain null removes the field). */
const JSON_NULL = "\0null";

$deep = 'leaf';
for ($i = 0; $i < 50; $i++) {
    $deep = ['n' => $deep];
}

/** The plaintext may hold bytes JSON cannot carry, so fixtures store it base64-encoded. */
function withPlaintext(array $vector): array
{
    $vector['plaintext_b64'] = base64_encode($vector['plaintext']);
    unset($vector['plaintext']);

    return $vector;
}

$cases = [];
$add = function (string $name, string $plaintext, string $expect, array $extra = []) use (&$cases): void {
    $cases[] = array_merge([
        'name' => $name,
        'plaintext' => $plaintext,
        'scope' => 'password-reset',
        'now' => NOW,
        'leeway' => 0,
        'expect' => $expect,
    ], $extra);
};

// Valid documents.
$add('valid', doc(), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_without_expiry', doc(['exp' => null]), 'ok', ['now' => 1999999999, 'data' => ['user' => 7], 'iat' => 1700000000]);
$add('valid_with_not_before', doc(['nbf' => 1700000050]), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'nbf' => 1700000050, 'exp' => 1700003600]);
$add('valid_one_second_before_expiry', doc(), 'ok', ['now' => 1700003599, 'data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_at_not_before', doc(['nbf' => NOW]), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'nbf' => NOW, 'exp' => 1700003600]);
$add('valid_integral_floats', '{"typ":"env","v":1.0,"iat":1700000000.0,"exp":1.7000036e9,"scope":"password-reset","data":1}', 'ok', ['data' => 1, 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_extra_fields_ignored', doc(['extra' => 'ignored', 'meta' => ['a' => 1]]), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_duplicate_key_last_wins', '{"typ":"env","v":1,"iat":1700000000,"exp":1700003600,"scope":"other","scope":"password-reset","data":2}', 'ok', ['data' => 2, 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_pretty_printed', json_encode(json_decode(doc()), JSON_PRETTY_PRINT), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('valid_negative_iat', doc(['iat' => -5]), 'ok', ['data' => ['user' => 7], 'iat' => -5, 'exp' => 1700003600]);

// Every kind of data.
foreach ([
    'data_null' => null,
    'data_string' => 'text',
    'data_empty_string' => '',
    'data_integer' => 42,
    'data_float' => 1.5,
    'data_true' => true,
    'data_false' => false,
    'data_list' => [1, 'two', [3], null],
    'data_empty_list' => [],
    'data_unicode' => 'Grüße 世界 🚀 "quoted" \\ / <tag> & ü',
    'data_nested' => ['a' => ['b' => ['c' => [1, 2, 3]]]],
    'data_deep' => $deep,
    'data_large' => str_repeat('0123456789', 2000),
] as $name => $value) {
    $add($name, doc(['data' => $value ?? JSON_NULL]), 'ok', ['data' => $value, 'iat' => 1700000000, 'exp' => 1700003600]);
}
$add('data_empty_object', '{"typ":"env","v":1,"iat":1700000000,"exp":1700003600,"scope":"password-reset","data":{}}', 'ok', ['data' => new stdClass(), 'iat' => 1700000000, 'exp' => 1700003600]);

// Scope.
$add('scope_unicode', doc(['scope' => 'ünï:☃ 🚀']), 'ok', ['scope' => 'ünï:☃ 🚀', 'data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('scope_mismatch', doc(), 'scope_mismatch', ['scope' => 'other']);
$add('scope_is_case_sensitive', doc(), 'scope_mismatch', ['scope' => 'Password-Reset']);
$add('scope_is_not_a_prefix_match', doc(['scope' => 'password-reset:extra']), 'scope_mismatch');
$add('scope_empty_in_token', doc(['scope' => '']), 'invalid', ['scope' => '']);
$add('scope_missing', doc(['scope' => null]), 'invalid');
$add('scope_not_a_string', doc(['scope' => 5]), 'invalid');
$add('scope_a_list', doc(['scope' => ['password-reset']]), 'invalid');

// Time.
$add('not_yet_valid', doc(['nbf' => 1700000200]), 'not_yet_valid');
$add('not_yet_valid_by_one_second', doc(['nbf' => NOW + 1]), 'not_yet_valid');
$add('not_yet_valid_within_leeway', doc(['nbf' => 1700000200]), 'ok', ['leeway' => 100, 'data' => ['user' => 7], 'iat' => 1700000000, 'nbf' => 1700000200, 'exp' => 1700003600]);
$add('not_yet_valid_beyond_leeway', doc(['nbf' => 1700000200]), 'not_yet_valid', ['leeway' => 99]);
$add('expired', doc(), 'expired', ['now' => 1700003601]);
$add('expired_exactly_at_exp', doc(), 'expired', ['now' => 1700003600]);
$add('expired_within_leeway', doc(), 'ok', ['now' => 1700003650, 'leeway' => 60, 'data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600]);
$add('expired_exactly_at_leeway_end', doc(), 'expired', ['now' => 1700003660, 'leeway' => 60]);
$add('expired_long_ago', doc(['exp' => 1]), 'expired');
$add('expired_negative_exp', doc(['exp' => -10]), 'expired');
$add('expiry_far_in_the_future', doc(['exp' => 4102444800]), 'ok', ['data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 4102444800]);

// The order of the checks.
$add('order_scope_before_expiry', doc(), 'scope_mismatch', ['scope' => 'other', 'now' => 1700003601]);
$add('order_not_before_before_expiry', doc(['nbf' => 1800000000]), 'not_yet_valid', ['now' => 1700003601]);
$add('order_version_before_scope', doc(['v' => 2]), 'unsupported_version', ['scope' => 'other']);
$add('order_version_before_other_fields', '{"typ":"env","v":2,"iat":"x","scope":5}', 'unsupported_version');
$add('order_structure_before_scope', doc(['iat' => null]), 'invalid', ['scope' => 'other']);
$add('order_structure_before_expiry', doc(['iat' => null]), 'invalid', ['now' => 1700003601]);

// Version and type.
$add('version_2', doc(['v' => 2]), 'unsupported_version');
$add('version_0', doc(['v' => 0]), 'unsupported_version');
$add('version_missing', doc(['v' => null]), 'invalid');
$add('version_string', doc(['v' => '1']), 'invalid');
$add('version_fractional', doc(['v' => 1.5]), 'invalid');
$add('version_null', '{"typ":"env","v":null,"iat":1700000000,"scope":"password-reset","data":1}', 'invalid');
$add('type_wrong', doc(['typ' => 'session']), 'invalid');
$add('type_missing', doc(['typ' => null]), 'invalid');
$add('type_upper_case', doc(['typ' => 'ENV']), 'invalid');
$add('type_not_a_string', doc(['typ' => 1]), 'invalid');

// Field types.
$add('iat_missing', doc(['iat' => null]), 'invalid');
$add('iat_string', doc(['iat' => '1700000000']), 'invalid');
$add('iat_fractional', doc(['iat' => 1700000000.5]), 'invalid');
$add('iat_null', '{"typ":"env","v":1,"iat":null,"scope":"password-reset","data":1}', 'invalid');
$add('exp_string', doc(['exp' => '1700003600']), 'invalid');
$add('exp_fractional', doc(['exp' => 1700003600.5]), 'invalid');
$add('exp_null', '{"typ":"env","v":1,"iat":1700000000,"exp":null,"scope":"password-reset","data":1}', 'invalid');
$add('exp_true', doc(['exp' => true]), 'invalid');
$add('exp_beyond_2_pow_53', '{"typ":"env","v":1,"iat":1700000000,"exp":1e300,"scope":"password-reset","data":1}', 'invalid');
$add('nbf_string', doc(['nbf' => '1']), 'invalid');
$add('nbf_null', '{"typ":"env","v":1,"iat":1700000000,"nbf":null,"scope":"password-reset","data":1}', 'invalid');
$add('data_missing', doc(['data' => null]), 'invalid');

// Not an envelope at all.
$add('plaintext_not_json', 'hello', 'invalid');
$add('plaintext_empty', '', 'invalid');
$add('plaintext_json_list', '[]', 'invalid');
$add('plaintext_json_scalar', '5', 'invalid');
$add('plaintext_json_null', 'null', 'invalid');
$add('plaintext_json_string', '"env"', 'invalid');
$add('plaintext_empty_object', '{}', 'invalid');
$add('plaintext_truncated_json', substr(doc(), 0, 40), 'invalid');
$add('plaintext_with_bom', "\xEF\xBB\xBF".doc(), 'invalid');
$add('plaintext_trailing_garbage', doc().'x', 'invalid');
$add('plaintext_invalid_utf8', "{\"typ\":\"env\",\"v\":1,\"iat\":1,\"scope\":\"a\xff\",\"data\":1}", 'invalid');
$add('plaintext_cookie_like', '8a3b2c1d4e5f60718293a4b5c6d7e8f901234567|abc123', 'invalid');

// Seal scenarios: the implementation seals with a fixed clock, PHP opens and compares.
$sealCases = [
    ['name' => 'in_one_hour', 'scope' => 'password-reset', 'data' => ['user' => 7], 'expiry' => ['in' => 3600], 'now' => 1700000000],
    ['name' => 'at_timestamp', 'scope' => 'invoice:download', 'data' => 'text', 'expiry' => ['at' => 1700009999], 'now' => 1700000000],
    ['name' => 'never', 'scope' => 'api', 'data' => null, 'expiry' => ['never' => true], 'now' => 1700000000],
    ['name' => 'with_not_before', 'scope' => 'delayed', 'data' => [1, 2, 3], 'expiry' => ['in' => 60], 'not_before' => 1700000030, 'now' => 1700000000],
    ['name' => 'unicode', 'scope' => 'ünï:☃ 🚀', 'data' => ['ü' => 'Grüße 世界 🚀 "q" \\ / <t> &'], 'expiry' => ['in' => 10], 'now' => 1700000000],
    ['name' => 'nested', 'scope' => 'deep', 'data' => ['a' => ['b' => [['c' => 1.5], false, null]]], 'expiry' => ['in' => 10], 'now' => 1700000000],
    ['name' => 'large', 'scope' => 'large', 'data' => str_repeat('0123456789', 2000), 'expiry' => ['in' => 10], 'now' => 1700000000],
    ['name' => 'empty_list', 'scope' => 'lists', 'data' => [], 'expiry' => ['in' => 10], 'now' => 1700000000],
];

$vectors = [];
foreach ($ciphers as $cipher) {
    $size = str_contains($cipher, '128') ? 16 : 32;
    $encrypter = new Encrypter(substr($keyBytes, 0, $size), $cipher);
    $previous = new Encrypter(substr($previousKeyBytes, 0, $size), $cipher);
    $stranger = new Encrypter(substr($strangerKeyBytes, 0, $size), $cipher);

    foreach ($cases as $case) {
        $vectors[] = withPlaintext($case + ['cipher' => $cipher, 'key' => 'current', 'token' => $encrypter->encryptString($case['plaintext'])]);
    }

    // Documents that are not made with encryptString(): what a session or a cookie holds.
    foreach ([
        ['name' => 'serialized_string', 'token' => $encrypter->encrypt('hello')],
        ['name' => 'serialized_array', 'token' => $encrypter->encrypt(['typ' => 'env', 'v' => 1])],
    ] as $odd) {
        $vectors[] = $odd + ['cipher' => $cipher, 'key' => 'current', 'scope' => 'password-reset', 'now' => NOW, 'leeway' => 0, 'expect' => 'invalid'];
    }

    // Key handling around the envelope.
    $vectors[] = ['name' => 'previous_key', 'cipher' => $cipher, 'key' => 'previous', 'plaintext_b64' => base64_encode(doc()), 'scope' => 'password-reset', 'now' => NOW, 'leeway' => 0,
        'expect' => 'ok', 'expect_without_previous_key' => 'decrypt_error', 'data' => ['user' => 7], 'iat' => 1700000000, 'exp' => 1700003600,
        'token' => $previous->encryptString(doc())];
    $vectors[] = ['name' => 'unrelated_key', 'cipher' => $cipher, 'key' => 'stranger', 'plaintext_b64' => base64_encode(doc()), 'scope' => 'password-reset', 'now' => NOW, 'leeway' => 0,
        'expect' => 'decrypt_error', 'token' => $stranger->encryptString(doc())];
    $vectors[] = ['name' => 'tampered', 'cipher' => $cipher, 'key' => 'current', 'plaintext_b64' => base64_encode(doc()), 'scope' => 'password-reset', 'now' => NOW, 'leeway' => 0,
        'expect' => 'decrypt_error', 'token' => (function () use ($encrypter) {
            $payload = json_decode(base64_decode($encrypter->encryptString(doc())), true);
            $payload['value'] = ($payload['value'][0] === 'A' ? 'B' : 'A').substr($payload['value'], 1);

            return base64_encode(json_encode($payload));
        })()];
}

file_put_contents(
    __DIR__.'/../fixtures/envelope-vectors.json',
    json_encode([
        'laravel' => \Composer\InstalledVersions::getVersion('illuminate/encryption'),
        'key_b64' => base64_encode($keyBytes),
        'previous_key_b64' => base64_encode($previousKeyBytes),
        'vectors' => $vectors,
        'seal_cases' => $sealCases,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION)."\n"
);

fwrite(STDERR, 'Wrote '.count($vectors).' envelope vectors and '.count($sealCases)." seal cases to fixtures/envelope-vectors.json\n");
