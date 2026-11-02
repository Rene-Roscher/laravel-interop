<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

use Closure;
use Illuminate\Contracts\Encryption\StringEncrypter;
use JsonException;
use stdClass;

/**
 * Interop Envelope v1: a JSON document with a scope, timestamps and data, encrypted with
 * Laravel's encryptString(). The encryption authenticates it, so the scope and the timestamps
 * cannot be changed without the key. Rust, Go and Node.js read and write the same format.
 */
final class Envelope
{
    public const TYPE = 'env';

    public const VERSION = 1;

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param  Closure(): int|null  $clock  Returns the current Unix time; defaults to time().
     */
    public function __construct(private readonly StringEncrypter $encrypter, ?Closure $clock = null)
    {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * Seals $data for $scope. The result is a string that is safe to hand to a client.
     *
     * @param  string  $scope  What the envelope may be used for, for example "password-reset".
     * @param  mixed  $data  Anything json_encode() accepts. Use (object) [] for an empty object.
     * @param  int|null  $notBefore  Unix timestamp before which the envelope is not valid.
     */
    public function seal(string $scope, mixed $data, Expiry $expiry, ?int $notBefore = null): string
    {
        if ($scope === '') {
            throw new \InvalidArgumentException('The scope must not be empty.');
        }

        $now = ($this->clock)();
        $document = [
            'typ' => self::TYPE,
            'v' => self::VERSION,
            'iat' => $now,
        ];
        if ($notBefore !== null) {
            $document['nbf'] = $notBefore;
        }
        if (($exp = $expiry->resolve($now)) !== null) {
            $document['exp'] = $exp;
        }
        $document['scope'] = $scope;
        $document['data'] = $data;

        return $this->encrypter->encryptString(
            json_encode($document, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)
        );
    }

    /**
     * Verifies and opens an envelope.
     *
     * The checks run in this order, and the first failure decides: valid structure, supported
     * version, matching scope, not before, expiry.
     *
     * @param  string  $scope  The scope the envelope has to have been sealed for.
     * @param  int  $leeway  Seconds of clock difference to tolerate on both time checks.
     * @param  int|null  $now  Overrides the current time, for tests.
     *
     * @throws EnvelopeException
     * @throws \Illuminate\Contracts\Encryption\DecryptException when the payload cannot be decrypted
     */
    public function open(string $token, string $scope, int $leeway = 0, ?int $now = null): Opened
    {
        $document = self::decode($this->encrypter->decryptString($token));

        $version = self::integer($document, 'v', required: true);
        if ($version !== self::VERSION) {
            throw new EnvelopeUnsupportedVersion();
        }

        $issuedAt = self::integer($document, 'iat', required: true);
        $notBefore = self::integer($document, 'nbf', required: false);
        $expiresAt = self::integer($document, 'exp', required: false);

        if (! property_exists($document, 'scope') || ! is_string($document->scope) || $document->scope === '') {
            throw new EnvelopeInvalid();
        }
        if (! property_exists($document, 'data')) {
            throw new EnvelopeInvalid();
        }

        if ($document->scope !== $scope) {
            throw new EnvelopeScopeMismatch();
        }

        $now ??= ($this->clock)();
        if ($notBefore !== null && $now < $notBefore - $leeway) {
            throw new EnvelopeNotYetValid();
        }
        if ($expiresAt !== null && $now >= $expiresAt + $leeway) {
            throw new EnvelopeExpired();
        }

        return new Opened($document->scope, self::toArray($document->data), $issuedAt, $notBefore, $expiresAt);
    }

    private static function decode(string $plaintext): stdClass
    {
        try {
            $document = json_decode($plaintext, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new EnvelopeInvalid();
        }

        if (! $document instanceof stdClass || ($document->typ ?? null) !== self::TYPE) {
            throw new EnvelopeInvalid();
        }

        return $document;
    }

    /**
     * Reads a timestamp or version field. Any JSON number without a fractional part is accepted,
     * because JavaScript cannot tell 1 from 1.0; everything else is invalid.
     */
    private static function integer(stdClass $document, string $name, bool $required): ?int
    {
        if (! property_exists($document, $name)) {
            return $required ? throw new EnvelopeInvalid() : null;
        }

        $value = $document->{$name};
        if (is_float($value) && is_finite($value) && floor($value) === $value && abs($value) < 2 ** 53) {
            return (int) $value;
        }
        if (! is_int($value)) {
            throw new EnvelopeInvalid();
        }

        return $value;
    }

    /** Turns decoded objects into arrays, so that data comes back as the array it was sealed from. */
    private static function toArray(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        }
        if (is_array($value)) {
            return array_map(self::toArray(...), $value);
        }

        return $value;
    }
}
