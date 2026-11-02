<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

final class EnvelopeInvalid extends EnvelopeException
{
    public const KIND = 'invalid';

    public function __construct(string $message = 'The payload is not a valid envelope.')
    {
        parent::__construct($message);
    }
}
