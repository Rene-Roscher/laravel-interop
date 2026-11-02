<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

final class EnvelopeNotYetValid extends EnvelopeException
{
    public const KIND = 'not_yet_valid';

    public function __construct(string $message = 'The envelope is not valid yet.')
    {
        parent::__construct($message);
    }
}
