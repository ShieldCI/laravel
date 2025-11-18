<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Suggests appropriate config files and keys for environment variables.
 *
 * Maps environment variable names to their conventional config file locations
 * following Laravel's naming conventions.
 */
class ConfigSuggester
{
    /**
     * Suggest config file and key for an environment variable.
     *
     * @return array{0: string, 1: string} [config_file, config_key]
     */
    public static function suggest(string $envVarName): array
    {
        $varLower = strtolower($envVarName);

        // App configuration
        if (str_starts_with($varLower, 'app_')) {
            $key = strtolower(substr($envVarName, 4));

            return ['app', "app.{$key}"];
        }

        // Database configuration
        if (str_starts_with($varLower, 'db_') || str_starts_with($varLower, 'database_')) {
            // Remove prefix using lowercase version for consistency
            $prefixLength = str_starts_with($varLower, 'database_') ? 9 : 3;
            $key = strtolower(substr($envVarName, $prefixLength));

            return ['database', "database.{$key}"];
        }

        // Cache configuration
        if (str_starts_with($varLower, 'cache_')) {
            $key = strtolower(substr($envVarName, 6));

            return ['cache', "cache.{$key}"];
        }

        // Mail configuration
        if (str_starts_with($varLower, 'mail_')) {
            $key = strtolower(substr($envVarName, 5));

            return ['mail', "mail.{$key}"];
        }

        // Queue configuration
        if (str_starts_with($varLower, 'queue_')) {
            $key = strtolower(substr($envVarName, 6));

            return ['queue', "queue.{$key}"];
        }

        // Session configuration
        if (str_starts_with($varLower, 'session_')) {
            $key = strtolower(substr($envVarName, 8));

            return ['session', "session.{$key}"];
        }

        // Logging configuration
        if (str_starts_with($varLower, 'log_')) {
            $key = strtolower(substr($envVarName, 4));

            return ['logging', "logging.{$key}"];
        }

        // Broadcasting configuration
        if (str_starts_with($varLower, 'broadcast_')) {
            $key = strtolower(substr($envVarName, 10));

            return ['broadcasting', "broadcasting.{$key}"];
        }

        // Filesystem configuration
        if (str_starts_with($varLower, 'filesystem_') || str_starts_with($varLower, 'aws_')) {
            // Remove prefix using lowercase version for consistency
            $prefixLength = str_starts_with($varLower, 'filesystem_') ? 11 : 4;
            $key = strtolower(substr($envVarName, $prefixLength));

            return ['filesystems', "filesystems.{$key}"];
        }

        // Default to custom config file
        return ['custom', 'custom.'.strtolower($envVarName)];
    }

    /**
     * Get a human-readable recommendation for replacing env() with config().
     */
    public static function getRecommendation(?string $varName): string
    {
        $base = 'Do not call env() outside of configuration files. Once config is cached (php artisan config:cache), the .env file is not loaded and env() returns null. ';

        if ($varName) {
            [$configFile, $configKey] = self::suggest($varName);

            return $base."Add '{$varName}' to a config file (e.g., config/{$configFile}.php) and use config('{$configKey}') instead of env('{$varName}').";
        }

        return $base.'Move this env() call to a configuration file and use config() to retrieve the value instead.';
    }
}
