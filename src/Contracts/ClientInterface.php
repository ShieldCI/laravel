<?php

declare(strict_types=1);

namespace ShieldCI\Contracts;

use ShieldCI\ValueObjects\AnalysisReport;

/**
 * Interface for communicating with ShieldCI API.
 */
interface ClientInterface
{
    /**
     * Send analysis report to ShieldCI API.
     */
    public function sendReport(AnalysisReport $report): bool;

    /**
     * Verify the API token is valid.
     */
    public function verifyToken(): bool;

    /**
     * Get the project details from API.
     */
    public function getProject(): ?array;
}
