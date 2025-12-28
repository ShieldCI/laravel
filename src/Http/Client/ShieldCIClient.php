<?php

declare(strict_types=1);

namespace ShieldCI\Http\Client;

use Illuminate\Support\Facades\Http;
use ShieldCI\Contracts\ClientInterface;
use ShieldCI\ValueObjects\AnalysisReport;

/**
 * HTTP client for communicating with ShieldCI API.
 */
class ShieldCIClient implements ClientInterface
{
    protected string $baseUrl;

    protected string $token;

    public function __construct()
    {
        $this->baseUrl = config('shieldci.api_url', 'https://api.shieldci.com');
        $this->token = config('shieldci.token', '');
    }

    public function sendReport(AnalysisReport $report): bool
    {
        try {
            $response = Http::withToken($this->token)
                ->timeout(30)
                ->post("{$this->baseUrl}/api/reports", $report->toArray());

            return $response->successful();
        } catch (\Exception $e) {
            // Log the error but don't throw - we don't want to fail analysis
            logger()->error('Failed to send report to ShieldCI API', [
                'error' => $e->getMessage(),
                'project_id' => $report->projectId,
            ]);

            return false;
        }
    }

    public function verifyToken(): bool
    {
        try {
            $response = Http::withToken($this->token)
                ->timeout(10)
                ->get("{$this->baseUrl}/api/verify");

            return $response->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    public function getProject(): ?array
    {
        try {
            $projectId = config('shieldci.project_id');

            if (empty($projectId)) {
                return null;
            }

            $response = Http::withToken($this->token)
                ->timeout(10)
                ->get("{$this->baseUrl}/api/projects/{$projectId}");

            if (! $response->successful()) {
                return null;
            }

            $data = $response->json();

            return is_array($data) ? $data : null;
        } catch (\Exception $e) {
            return null;
        }
    }
}
