<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Parses php.ini-style memory limit values so the analyze command can treat
 * the configured limit as a floor: raise a lower ambient limit, but never
 * lower a higher one (e.g. Vapor's 2048M runtime default or an unlimited CLI).
 */
final class MemoryLimit
{
    /**
     * Convert a php.ini-style memory limit ('512M', '1G', '-1') to bytes.
     *
     * Returns INF for unlimited (-1) and null when the value is unparseable.
     */
    public static function toBytes(string $limit): ?float
    {
        $limit = trim($limit);

        if ($limit === '-1') {
            return INF;
        }

        if (preg_match('/^(\d+)([KMGkmg])?$/', $limit, $matches) !== 1) {
            return null;
        }

        $bytes = (float) $matches[1];

        return match (strtoupper($matches[2] ?? '')) {
            'K' => $bytes * 1024,
            'M' => $bytes * 1024 * 1024,
            'G' => $bytes * 1024 * 1024 * 1024,
            default => $bytes,
        };
    }

    /**
     * Whether the configured limit should replace the current one.
     *
     * The configured value acts as a floor: apply it only when it is strictly
     * higher than the current limit. An unparseable configured value is never
     * applied; an unparseable current value is treated as replaceable.
     */
    public static function shouldRaise(string $current, string $configured): bool
    {
        $configuredBytes = self::toBytes($configured);
        if ($configuredBytes === null) {
            return false;
        }

        $currentBytes = self::toBytes($current);
        if ($currentBytes === null) {
            return true;
        }

        return $configuredBytes > $currentBytes;
    }
}
