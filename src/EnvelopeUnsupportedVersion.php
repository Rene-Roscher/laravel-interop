<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

final class EnvelopeUnsupportedVersion extends EnvelopeException
{
    public const KIND = 'unsupported_version';

    public function __construct(string $message = 'The envelope version is not supported.')
    {
        parent::__construct($message);
    }
}
