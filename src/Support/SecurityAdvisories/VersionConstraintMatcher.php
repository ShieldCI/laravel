<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

use function explode;
use function ltrim;
use function strpos;
use function trim;

class VersionConstraintMatcher
{
    /**
     * @param  array<int, string>|string  $constraints
     */
    public function matches(string $version, array|string $constraints): bool
    {
        $constraints = is_array($constraints) ? $constraints : [$constraints];

        foreach ($constraints as $constraint) {
            $constraint = trim((string) $constraint);

            if ($constraint === '' || $constraint === '*') {
                return true;
            }

            if ($this->matchOperatorConstraint($version, $constraint)) {
                return true;
            }

            if ($this->matchCaretConstraint($version, $constraint)) {
                return true;
            }

            if ($this->matchTildeConstraint($version, $constraint)) {
                return true;
            }

            if ($this->matchWildcardConstraint($version, $constraint)) {
                return true;
            }
        }

        return false;
    }

    private function matchOperatorConstraint(string $version, string $constraint): bool
    {
        if (! preg_match('/^(<=|>=|<|>|==|=)?\s*v?([0-9][0-9A-Za-z\.-]*)$/', $constraint, $matches)) {
            return false;
        }

        $operator = $matches[1] !== '' ? $matches[1] : '==';
        $target = $matches[2];

        return version_compare($version, $target, $operator);
    }

    private function matchCaretConstraint(string $version, string $constraint): bool
    {
        if (! str_starts_with($constraint, '^')) {
            return false;
        }

        $base = ltrim(substr($constraint, 1));
        if ($base === '') {
            return false;
        }

        $parts = explode('.', $base);
        $major = (int) ($parts[0] ?? 0);
        $upperMajor = (string) ($major + 1);
        $lowerBound = $base;
        $upperBound = $upperMajor.'.0.0';

        return version_compare($version, $lowerBound, '>=')
            && version_compare($version, $upperBound, '<');
    }

    private function matchTildeConstraint(string $version, string $constraint): bool
    {
        if (! str_starts_with($constraint, '~')) {
            return false;
        }

        $base = ltrim(substr($constraint, 1));
        if ($base === '') {
            return false;
        }

        $parts = explode('.', $base);
        $lowerBound = $base;

        if (count($parts) >= 2) {
            $major = (int) $parts[0];
            $minor = (int) $parts[1];
            $upperBound = $major.'.'.($minor + 1).'.0';
        } else {
            $major = (int) $parts[0];
            $upperBound = ($major + 1).'.0.0';
        }

        return version_compare($version, $lowerBound, '>=')
            && version_compare($version, $upperBound, '<');
    }

    private function matchWildcardConstraint(string $version, string $constraint): bool
    {
        if (strpos($constraint, '*') === false && str_ends_with($constraint, '.x') === false) {
            return false;
        }

        $normalized = str_replace(['*', 'x'], '', $constraint);
        $normalized = rtrim($normalized, '.');

        return str_starts_with($version, $normalized);
    }
}
