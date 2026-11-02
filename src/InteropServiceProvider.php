<?php

declare(strict_types=1);

namespace ReneRoscher\Interop;

use Illuminate\Support\ServiceProvider;

/** Binds Envelope to the application's encrypter, so that app(Envelope::class) works. */
final class InteropServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Envelope::class, fn ($app) => new Envelope($app->make('encrypter')));
    }
}
