<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

/** A verified envelope. */
final class Opened
{
    public function __construct(
        public readonly string $scope,
        public readonly mixed $data,
        public readonly int $issuedAt,
        public readonly ?int $notBefore,
        public readonly ?int $expiresAt,
    ) {
    }
}
