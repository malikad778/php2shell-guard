<?php

namespace Malikad\Php2ShellGuard\Laravel;

if (!class_exists('Illuminate\Support\ServiceProvider')) {
    abstract class BaseServiceProvider
    {
        protected $app;
        public function __construct($app = null) { $this->app = $app; }
        public function commands($commands) {}
        public function publishes(array $paths, $groups = null) {}
    }
} else {
    class_alias('Illuminate\Support\ServiceProvider', 'Malikad\Php2ShellGuard\Laravel\BaseServiceProvider');
}

class Php2ShellGuardServiceProvider extends BaseServiceProvider
{
    public function register()
    {
        $this->commands(array(
            Command::class,
        ));
    }

    public function boot()
    {
        if (function_exists('config_path')) {
            $this->publishes(array(
                __DIR__ . '/../../templates/php-ini/99-php2shell-mitigation.ini' => config_path('php2shell-guard.ini'),
            ), 'php2shell-guard-config');
        }
    }
}
