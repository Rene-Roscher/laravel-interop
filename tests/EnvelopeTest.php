<?php

declare(strict_types=1);

namespace ReneRoscher\Interop\Tests;

use Illuminate\Container\Container;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReneRoscher\Interop\Envelope;
use ReneRoscher\Interop\EnvelopeException;
use ReneRoscher\Interop\EnvelopeExpired;
use ReneRoscher\Interop\EnvelopeInvalid;
use ReneRoscher\Interop\EnvelopeNotYetValid;
use ReneRoscher\Interop\EnvelopeScopeMismatch;
use ReneRoscher\Interop\EnvelopeUnsupportedVersion;
use ReneRoscher\Interop\Expiry;
use ReneRoscher\Interop\InteropServiceProvider;

final class EnvelopeTest extends TestCase
{
    private const NOW = 1700000000;

    private static function encrypter(string $cipher = 'aes-256-cbc', string $byte = "\x2b"): Encrypter
    {
        return new Encrypter(str_repeat($byte, str_contains($cipher, '128') ? 16 : 32), $cipher);
    }

    private function envelope(string $cipher = 'aes-256-cbc', int $now = self::NOW): Envelope
    {
        return new Envelope(self::encrypter($cipher), static fn (): int => $now);
    }

    public function test_it_round_trips_every_kind_of_data_for_every_cipher(): void
    {
        $values = [null, true, false, 0, -7, 1.5, '', 'text', [], [1, 'two', [3]], ['a' => ['b' => null]], 'Grüße 世界 🚀'];
        foreach (['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm'] as $cipher) {
            $envelope = $this->envelope($cipher);
            foreach ($values as $value) {
                $opened = $envelope->open($envelope->seal('test', $value, Expiry::in(60)), 'test');
                $this->assertSame($value, $opened->data);
                $this->assertSame('test', $opened->scope);
            }
        }
    }

    public function test_it_reports_the_timestamps(): void
    {
        $envelope = $this->envelope();

        $opened = $envelope->open($envelope->seal('s', 1, Expiry::in(3600), notBefore: self::NOW + 10), 's', leeway: 10);
        $this->assertSame(self::NOW, $opened->issuedAt);
        $this->assertSame(self::NOW + 10, $opened->notBefore);
        $this->assertSame(self::NOW + 3600, $opened->expiresAt);

        $opened = $envelope->open($envelope->seal('s', 1, Expiry::never()), 's');
        $this->assertNull($opened->expiresAt);
        $this->assertNull($opened->notBefore);

        $opened = $envelope->open($envelope->seal('s', 1, Expiry::at(self::NOW + 99)), 's');
        $this->assertSame(self::NOW + 99, $opened->expiresAt);
    }

    public function test_the_expiry_has_to_be_chosen(): void
    {
        $this->expectException(\ArgumentCountError::class);
        $this->envelope()->seal('s', 1); // @phpstan-ignore-line
    }

    public function test_a_lifetime_has_to_be_positive(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Expiry::in(0);
    }

    public function test_a_timestamp_has_to_be_positive(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Expiry::at(-1);
    }

    public function test_the_scope_must_not_be_empty(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->envelope()->seal('', 1, Expiry::never());
    }

    public function test_it_checks_the_scope_expiry_and_not_before_with_the_clock(): void
    {
        $token = $this->envelope()->seal('s', 1, Expiry::in(100), notBefore: self::NOW + 50);

        $this->assertThrowsKind(EnvelopeNotYetValid::class, fn () => $this->envelope(now: self::NOW + 49)->open($token, 's'));
        $this->assertSame(1, $this->envelope(now: self::NOW + 50)->open($token, 's')->data);
        $this->assertSame(1, $this->envelope(now: self::NOW + 99)->open($token, 's')->data);
        $this->assertThrowsKind(EnvelopeExpired::class, fn () => $this->envelope(now: self::NOW + 100)->open($token, 's'));
        $this->assertThrowsKind(EnvelopeScopeMismatch::class, fn () => $this->envelope(now: self::NOW + 60)->open($token, 'other'));
    }

    public function test_the_leeway_widens_both_time_checks(): void
    {
        $token = $this->envelope()->seal('s', 1, Expiry::in(100), notBefore: self::NOW + 50);
        $at = fn (int $now, int $leeway) => $this->envelope()->open($token, 's', leeway: $leeway, now: $now)->data;

        $this->assertSame(1, $at(self::NOW + 40, 10));
        $this->assertThrowsKind(EnvelopeNotYetValid::class, fn () => $at(self::NOW + 39, 10));
        $this->assertSame(1, $at(self::NOW + 109, 10));
        $this->assertThrowsKind(EnvelopeExpired::class, fn () => $at(self::NOW + 110, 10));
    }

    public function test_it_uses_the_real_clock_by_default(): void
    {
        $envelope = new Envelope(self::encrypter());
        $this->assertSame('x', $envelope->open($envelope->seal('s', 'x', Expiry::in(60)), 's')->data);
        $this->assertThrowsKind(EnvelopeExpired::class, fn () => $envelope->open($envelope->seal('s', 'x', Expiry::at(1)), 's'));
    }

    public function test_the_previous_keys_of_the_encrypter_apply(): void
    {
        $old = new Envelope(self::encrypter(byte: "\x7a"), static fn (): int => self::NOW);
        $token = $old->seal('s', 'legacy', Expiry::in(60));

        $rotated = self::encrypter()->previousKeys([str_repeat("\x7a", 32)]);
        $this->assertSame('legacy', (new Envelope($rotated, static fn (): int => self::NOW))->open($token, 's')->data);

        $this->expectException(DecryptException::class);
        $this->envelope()->open($token, 's');
    }

    public function test_a_payload_that_does_not_decrypt_is_a_decrypt_exception_not_an_envelope_exception(): void
    {
        $this->expectException(DecryptException::class);
        $this->envelope()->open('not a payload', 's');
    }

    public function test_only_encrypted_strings_are_envelopes(): void
    {
        $encrypter = self::encrypter();
        foreach ([$encrypter->encrypt('hello'), $encrypter->encrypt(['typ' => 'env', 'v' => 1]), $encrypter->encryptString('hello')] as $token) {
            $this->assertThrowsKind(EnvelopeInvalid::class, fn () => $this->envelope()->open($token, 's'));
        }
    }

    public function test_the_service_provider_binds_the_applications_encrypter(): void
    {
        $container = new Container();
        $container->instance('encrypter', self::encrypter());
        (new InteropServiceProvider($container))->register();

        $envelope = $container->make(Envelope::class);
        $this->assertSame(['a' => 1], $envelope->open($envelope->seal('s', ['a' => 1], Expiry::in(60)), 's')->data);
        $this->assertSame($envelope, $container->make(Envelope::class));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function vectors(): iterable
    {
        $file = json_decode((string) file_get_contents(__DIR__.'/../fixtures/envelope-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        foreach ($file['vectors'] as $vector) {
            yield $vector['cipher'].'/'.$vector['name'] => [$vector, $file];
        }
    }

    /**
     * @param  array<string, mixed>  $vector
     * @param  array<string, mixed>  $file
     */
    #[DataProvider('vectors')]
    public function test_every_vector_gets_its_verdict(array $vector, array $file): void
    {
        $size = str_contains($vector['cipher'], '128') ? 16 : 32;
        $current = substr(base64_decode($file['key_b64']), 0, $size);
        $previous = substr(base64_decode($file['previous_key_b64']), 0, $size);

        // Tokens from the previous key are opened by an application that rotated its key.
        $encrypter = new Encrypter($current, $vector['cipher']);
        $rotated = (new Encrypter($current, $vector['cipher']))->previousKeys([$previous]);
        $withoutPrevious = new Envelope($encrypter);
        $envelope = new Envelope($vector['key'] === 'previous' ? $rotated : $encrypter);

        $verdict = self::verdict($envelope, $vector);
        $this->assertSame($vector['expect'], $verdict['kind'], $vector['name']);

        if (isset($vector['expect_without_previous_key'])) {
            $this->assertSame($vector['expect_without_previous_key'], self::verdict($withoutPrevious, $vector)['kind']);
        }

        if ($vector['expect'] === 'ok') {
            $opened = $verdict['opened'];
            $this->assertSame($vector['iat'], $opened->issuedAt);
            $this->assertSame($vector['nbf'] ?? null, $opened->notBefore);
            $this->assertSame($vector['exp'] ?? null, $opened->expiresAt);
            $this->assertEquals($vector['data'], $opened->data);
        }
    }

    /**
     * @param  array<string, mixed>  $vector
     * @return array{kind: string, opened?: \ReneRoscher\Interop\Opened}
     */
    private static function verdict(Envelope $envelope, array $vector): array
    {
        try {
            $opened = $envelope->open($vector['token'], $vector['scope'], $vector['leeway'], $vector['now']);

            return ['kind' => 'ok', 'opened' => $opened];
        } catch (EnvelopeException $e) {
            return ['kind' => $e->kind()];
        } catch (DecryptException) {
            return ['kind' => 'decrypt_error'];
        }
    }

    public function test_the_kinds_are_the_shared_verdict_names(): void
    {
        $this->assertSame('invalid', (new EnvelopeInvalid())->kind());
        $this->assertSame('unsupported_version', (new EnvelopeUnsupportedVersion())->kind());
        $this->assertSame('scope_mismatch', (new EnvelopeScopeMismatch())->kind());
        $this->assertSame('not_yet_valid', (new EnvelopeNotYetValid())->kind());
        $this->assertSame('expired', (new EnvelopeExpired())->kind());
    }

    private function assertThrowsKind(string $class, callable $callback): void
    {
        try {
            $callback();
        } catch (EnvelopeException $e) {
            $this->assertInstanceOf($class, $e);

            return;
        }
        $this->fail("Expected $class");
    }
}
