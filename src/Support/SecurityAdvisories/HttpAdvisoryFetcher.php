<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Throwable;

class HttpAdvisoryFetcher implements AdvisoryFetcherInterface
{
    public const DEFAULT_SOURCE = 'https://api.osv.dev/v1/querybatch';

    public function __construct(
        private ClientInterface $client,
        private ?LoggerInterface $logger = null,
        private string $apiUrl = self::DEFAULT_SOURCE,
        private int $timeoutSeconds = 10,
    ) {}

    public function fetch(array $dependencies): array
    {
        $queries = $this->buildQueries($dependencies);

        if (empty($queries)) {
            return [];
        }

        try {
            $response = $this->client->request('POST', $this->apiUrl, [
                'timeout' => $this->timeoutSeconds,
                'json' => ['queries' => $queries],
            ]);

            if ($response->getStatusCode() !== 200) {
                return [];
            }

            $decoded = json_decode((string) $response->getBody(), true);

            if (! is_array($decoded) || ! isset($decoded['results']) || ! is_array($decoded['results'])) {
                return [];
            }

            return $this->mapResults($decoded['results'], $queries);
        } catch (Throwable $exception) {
            $this->logFailure($exception);

            return [];
        }
    }

    /**
     * @param  array<string, array{version: string, time: string|null}>  $dependencies
     * @return array<int, array<string, mixed>>
     */
    private function buildQueries(array $dependencies): array
    {
        $queries = [];

        foreach ($dependencies as $package => $info) {
            $version = $info['version'] ?? null;

            if (! is_string($package) || $package === '' || ! is_string($version)) {
                continue;
            }

            $queries[] = [
                'package' => [
                    'name' => $package,
                    'ecosystem' => 'Packagist',
                ],
                'version' => $version,
            ];
        }

        return $queries;
    }

    /**
     * @param  array<int, array<string, mixed>>  $results
     * @param  array<int, array<string, mixed>>  $queries
     * @return array<string, array<int, array<string, mixed>>>
     */
    private function mapResults(array $results, array $queries): array
    {
        $advisories = [];

        foreach ($results as $index => $result) {
            if (! isset($queries[$index])) {
                continue;
            }

            $package = $queries[$index]['package']['name'];
            $version = $queries[$index]['version'];

            if (! is_string($package) || ! is_string($version)) {
                continue;
            }

            if (! isset($result['vulns']) || ! is_array($result['vulns'])) {
                continue;
            }

            foreach ($result['vulns'] as $vuln) {
                if (! is_array($vuln)) {
                    continue;
                }

                $advisories[$package][] = $this->formatVulnerability($vuln, $version);
            }
        }

        return $advisories;
    }

    /**
     * @param  array<string, mixed>  $vuln
     */
    private function formatVulnerability(array $vuln, string $version): array
    {
        $cve = null;

        if (isset($vuln['aliases']) && is_array($vuln['aliases'])) {
            foreach ($vuln['aliases'] as $alias) {
                if (is_string($alias) && str_starts_with($alias, 'CVE-')) {
                    $cve = $alias;
                    break;
                }
            }
        }

        $link = null;
        if (isset($vuln['references']) && is_array($vuln['references'])) {
            foreach ($vuln['references'] as $reference) {
                if (isset($reference['url']) && is_string($reference['url'])) {
                    $link = $reference['url'];
                    break;
                }
            }
        }

        return [
            'title' => isset($vuln['summary']) && is_string($vuln['summary'])
                ? $vuln['summary']
                : ($vuln['id'] ?? 'Known vulnerability'),
            'cve' => $cve,
            'link' => $link,
            'affected_versions' => [$version],
        ];
    }

    private function logFailure(Throwable $exception): void
    {
        if ($this->logger !== null) {
            $this->logger->warning('Failed to fetch security advisories: '.$exception->getMessage());
        }
    }
}
