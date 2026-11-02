<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

final class EnvelopeScopeMismatch extends EnvelopeException
{
    public const KIND = 'scope_mismatch';

    public function __construct(string $message = 'The envelope was issued for another scope.')
    {
        parent::__construct($message);
    }
}
