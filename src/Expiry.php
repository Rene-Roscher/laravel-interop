<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

use InvalidArgumentException;

/**
 * When an envelope stops being valid. Sealing requires an explicit choice, so that a token
 * never lives forever by accident.
 */
final class Expiry
{
    private function __construct(
        public readonly ?int $seconds,
        public readonly ?int $timestamp,
    ) {
    }

    /** Valid for this many seconds after it is sealed. */
    public static function in(int $seconds): self
    {
        if ($seconds <= 0) {
            throw new InvalidArgumentException('The lifetime must be a positive number of seconds.');
        }

        return new self($seconds, null);
    }

    /** Valid until this Unix timestamp (seconds, UTC). */
    public static function at(int $timestamp): self
    {
        if ($timestamp <= 0) {
            throw new InvalidArgumentException('The expiry must be a positive Unix timestamp.');
        }

        return new self(null, $timestamp);
    }

    /** Never expires. Prefer a lifetime unless the scope itself limits the token. */
    public static function never(): self
    {
        return new self(null, null);
    }

    /** The Unix timestamp at which an envelope sealed at $now expires, or null. */
    public function resolve(int $now): ?int
    {
        return $this->timestamp ?? ($this->seconds !== null ? $now + $this->seconds : null);
    }
}
