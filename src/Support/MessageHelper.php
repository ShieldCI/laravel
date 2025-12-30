<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Helper utilities for message formatting and sanitization.
 */
class MessageHelper
{
    /**
     * Sanitize error message for display in recommendations.
     *
     * Limits error message length to prevent overly long recommendations
     * that could make the output hard to read.
     */
    public static function sanitizeErrorMessage(string $error, int $maxLength = 200): string
    {
        if (strlen($error) > $maxLength) {
            return substr($error, 0, $maxLength).'...';
        }

        return $error;
    }
}
