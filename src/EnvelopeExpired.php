<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

final class EnvelopeExpired extends EnvelopeException
{
    public const KIND = 'expired';

    public function __construct(string $message = 'The envelope has expired.')
    {
        parent::__construct($message);
    }
}
