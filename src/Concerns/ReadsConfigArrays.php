<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

/**
 * Reads Laravel config values at their declared types.
 *
 * Laravel's config() helper is typed as mixed, so an is_array() check only
 * proves array<mixed, mixed> and a raw offset read yields mixed. These helpers
 * coerce a config value to the type a property expects, falling back to the
 * caller's default whenever the stored value is missing or the wrong shape.
 */
trait ReadsConfigArrays
{
    /**
     * Coerce a value into a string-keyed array, dropping any non-string keys.
     *
     * @return array<string, mixed>
     */
    protected function toStringKeyedArray(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $stringKeyed = [];

        foreach ($value as $key => $item) {
            if (is_string($key)) {
                $stringKeyed[$key] = $item;
            }
        }

        return $stringKeyed;
    }

    /**
     * Read an integer entry from a mixed config value.
     */
    protected function configInt(mixed $config, string $key, int $default): int
    {
        $value = is_array($config) ? ($config[$key] ?? null) : null;

        return is_int($value) ? $value : $default;
    }

    /**
     * Read a boolean entry from a mixed config value.
     */
    protected function configBool(mixed $config, string $key, bool $default): bool
    {
        $value = is_array($config) ? ($config[$key] ?? null) : null;

        return is_bool($value) ? $value : $default;
    }

    /**
     * Read a list-of-strings entry from a mixed config value, dropping non-strings.
     *
     * @param  array<int, string>  $default
     * @return array<int, string>
     */
    protected function configStringList(mixed $config, string $key, array $default): array
    {
        $value = is_array($config) ? ($config[$key] ?? null) : null;

        return is_array($value) ? array_values(array_filter($value, 'is_string')) : $default;
    }
}
