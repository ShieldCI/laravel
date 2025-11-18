<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Detects the type of a Laravel application file based on its path.
 *
 * Classifies files into categories like controller, model, service, etc.
 * for better issue reporting and categorization.
 */
class FileTypeDetector
{
    /**
     * Map of path patterns to file types.
     *
     * @var array<string, string>
     */
    private const PATH_PATTERNS = [
        '/app/Http/Controllers/' => 'controller',
        '/app/Models/' => 'model',
        '/app/Services/' => 'service',
        '/app/Http/Middleware/' => 'middleware',
        '/app/Providers/' => 'provider',
        '/app/Console/' => 'console',
        '/app/Jobs/' => 'job',
        '/app/Events/' => 'event',
        '/app/Listeners/' => 'listener',
        '/app/Policies/' => 'policy',
        '/routes/' => 'route',
        '/resources/views/' => 'view',
        '/database/migrations/' => 'migration',
        '/database/seeders/' => 'seeder',
        '/database/factories/' => 'factory',
    ];

    /**
     * Detect the file type based on its path.
     */
    public static function detect(string $filePath): string
    {
        foreach (self::PATH_PATTERNS as $pattern => $type) {
            if (str_contains($filePath, $pattern)) {
                return $type;
            }
        }

        return 'application';
    }

    /**
     * Check if a file is of a specific type.
     */
    public static function is(string $filePath, string $type): bool
    {
        return self::detect($filePath) === $type;
    }

    /**
     * Get all supported file types.
     *
     * @return array<int, string>
     */
    public static function supportedTypes(): array
    {
        return array_unique(array_values(self::PATH_PATTERNS));
    }
}
