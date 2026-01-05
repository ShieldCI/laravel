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
     * Redacts sensitive information (passwords, credentials, API keys)
     * and limits message length to prevent overly long recommendations.
     */
    public static function sanitizeErrorMessage(string $error, int $maxLength = 200): string
    {
        // First, redact sensitive information
        $sanitized = self::redactSensitiveInfo($error);

        // Then truncate if needed
        if (strlen($sanitized) > $maxLength) {
            return substr($sanitized, 0, $maxLength).'...';
        }

        return $sanitized;
    }

    /**
     * Redact sensitive information from error messages.
     *
     * Removes passwords, API keys, tokens, and credentials from error messages
     * while preserving enough context for debugging.
     */
    private static function redactSensitiveInfo(string $message): string
    {
        // Redact connection strings with credentials
        // Examples: redis://user:pass@host, mysql://user:pass@host, mongodb://user:pass@host
        // Matches everything from :// to @ (greedy to handle passwords with special chars)
        $message = preg_replace(
            '#(\w+://)([^/\s]+)@#i',
            '$1***:***@',
            $message
        ) ?? $message;

        // Redact password parameters
        // Examples: password=secret, pwd=secret, pass=secret, passwd=secret
        $message = preg_replace(
            '/(password|passwd|pwd|pass)(\s*=\s*)[^\s&;,)\]]+/i',
            '$1$2***',
            $message
        ) ?? $message;

        // Redact API keys and tokens
        // Examples: api_key=xxx, apikey=xxx, auth_token=xxx
        $message = preg_replace(
            '/(api[_-]?key|auth[_-]?token)(\s*[=:]\s*)[^\s&;,)\]]+/i',
            '$1$2***',
            $message
        ) ?? $message;

        // Redact bearer tokens (format: "bearer <token>")
        $message = preg_replace(
            '/\bbearer\s+[^\s&;,)\]]+/i',
            'bearer ***',
            $message
        ) ?? $message;

        // Redact generic token= parameters
        $message = preg_replace(
            '/\btoken\s*=\s*[^\s&;,)\]]+/i',
            'token=***',
            $message
        ) ?? $message;

        // Redact private keys and secrets
        // Examples: private_key=xxx, secret=xxx, client_secret=xxx
        $message = preg_replace(
            '/(private[_-]?key|secret|client[_-]?secret)(\s*=\s*)[^\s&;,)\]]+/i',
            '$1$2***',
            $message
        ) ?? $message;

        // Redact AWS-style access keys (pattern: AKIA followed by 16 chars)
        $message = preg_replace(
            '/AKIA[0-9A-Z]{16}/i',
            'AKIA***',
            $message
        ) ?? $message;

        // Redact what looks like internal IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        $message = preg_replace(
            '/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/',
            '***.*.*.*',
            $message
        ) ?? $message;

        return $message;
    }
}
