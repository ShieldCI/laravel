<?php

declare(strict_types=1);

namespace ShieldCI\Contracts;

/**
 * Interface for the ShieldCI API client.
 */
interface ClientInterface
{
    /**
     * Send an analysis report to the ShieldCI platform.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    public function sendReport(array $payload): array;

    /**
     * Verify the API token is valid.
     *
     * @return array<string, mixed>
     */
    public function verifyToken(): array;

    /**
     * Get project information from the platform.
     *
     * @return array<string, mixed>
     */
    public function getProject(): array;
}
