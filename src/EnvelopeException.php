<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

use RuntimeException;

/**
 * Base class of everything that makes an envelope unusable. A failure to decrypt is not one of
 * them: it is Laravel's DecryptException, thrown before the envelope is looked at.
 */
class EnvelopeException extends RuntimeException
{
    /** The verdict name shared by all implementations (see the README). */
    public const KIND = 'invalid';

    public function kind(): string
    {
        return static::KIND;
    }
}
