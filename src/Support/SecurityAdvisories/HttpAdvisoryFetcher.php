<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Throwable;

class HttpAdvisoryFetcher implements AdvisoryFetcherInterface
{
    public const DEFAULT_SOURCE = 'https://api.osv.dev/v1/querybatch';

    public const DEFAULT_VULN_SOURCE = 'https://api.osv.dev/v1/vulns';

    private string $vulnUrl;

    public function __construct(
        private ClientInterface $client,
        private ?LoggerInterface $logger = null,
        private string $apiUrl = self::DEFAULT_SOURCE,
        private int $timeoutSeconds = 10,
        ?string $vulnUrl = null,
    ) {
        $this->vulnUrl = $vulnUrl ?? $this->deriveVulnUrl($apiUrl);
    }

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

            /** @var array<int, array<string, mixed>> $results */
            $results = $decoded['results'];

            // querybatch only returns {id, modified}; resolve the full records
            // (summary, aliases, references, affected ranges) per vuln id.
            $details = $this->hydrateVulnerabilities($results, $queries);

            return $this->mapResults($results, $queries, $details);
        } catch (Throwable $exception) {
            $this->logFailure($exception);

            return [];
        }
    }

    /**
     * @param  array<string, array{version: string, time: string|null}>  $dependencies
     * @return array<int, array{package: array{name: string, ecosystem: string}, version: string}>
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
     * Resolve full vulnerability records for every vuln id returned by the batch
     * query. OSV's querybatch endpoint returns only {id, modified}, so details
     * must be fetched individually via GET /v1/vulns/{id}. Failures fail open
     * (recorded as null so the caller still reports a minimal advisory).
     *
     * @param  array<int, array<string, mixed>>  $results
     * @param  array<int, array<string, mixed>>  $queries
     * @return array<string, array<string, mixed>|null> keyed by vuln id
     */
    private function hydrateVulnerabilities(array $results, array $queries): array
    {
        $details = [];

        foreach ($this->collectVulnIds($results, $queries) as $id) {
            $details[$id] = $this->fetchVulnerability($id);
        }

        return $details;
    }

    /**
     * @param  array<int, array<string, mixed>>  $results
     * @param  array<int, array<string, mixed>>  $queries
     * @return array<int, string>
     */
    private function collectVulnIds(array $results, array $queries): array
    {
        $ids = [];

        foreach ($results as $index => $result) {
            if (! isset($queries[$index])) {
                continue;
            }

            if (! is_array($result) || ! isset($result['vulns']) || ! is_array($result['vulns'])) {
                continue;
            }

            foreach ($result['vulns'] as $vuln) {
                if (is_array($vuln) && isset($vuln['id']) && is_string($vuln['id']) && $vuln['id'] !== '') {
                    $ids[$vuln['id']] = true;
                }
            }
        }

        return array_keys($ids);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchVulnerability(string $id): ?array
    {
        try {
            $response = $this->client->request('GET', $this->vulnUrl.'/'.rawurlencode($id), [
                'timeout' => $this->timeoutSeconds,
            ]);

            if ($response->getStatusCode() !== 200) {
                return null;
            }

            $decoded = json_decode((string) $response->getBody(), true);

            if (! is_array($decoded)) {
                return null;
            }

            /** @var array<string, mixed> $decoded */
            return $decoded;
        } catch (Throwable $exception) {
            $this->logFailure($exception);

            return null;
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $results
     * @param  array<int, array{package: array{name: string, ecosystem: string}, version: string}>  $queries
     * @param  array<string, array<string, mixed>|null>  $details
     * @return array<string, array<int, array<string, mixed>>>
     */
    private function mapResults(array $results, array $queries, array $details): array
    {
        $advisories = [];

        foreach ($results as $index => $result) {
            if (! isset($queries[$index])) {
                continue;
            }

            $package = $queries[$index]['package']['name'];

            if (! is_array($result) || ! isset($result['vulns']) || ! is_array($result['vulns'])) {
                continue;
            }

            foreach ($result['vulns'] as $stub) {
                if (! is_array($stub) || ! isset($stub['id']) || ! is_string($stub['id'])) {
                    continue;
                }

                // Prefer the hydrated full record; fall back to the batch stub if
                // hydration failed so a real OSV hit is never silently dropped.
                $full = $details[$stub['id']] ?? null;
                $vuln = is_array($full) ? $full : $stub;

                $advisories[$package][] = $this->formatVulnerability($vuln, $package);
            }
        }

        return $advisories;
    }

    /**
     * @param  array<string, mixed>  $vuln
     * @return array<string, mixed>
     */
    private function formatVulnerability(array $vuln, string $package): array
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
                if (is_array($reference) && isset($reference['url']) && is_string($reference['url'])) {
                    $link = $reference['url'];
                    break;
                }
            }
        }

        $id = isset($vuln['id']) && is_string($vuln['id']) ? $vuln['id'] : null;

        return [
            'title' => isset($vuln['summary']) && is_string($vuln['summary'])
                ? $vuln['summary']
                : ($id ?? 'Known vulnerability'),
            'cve' => $cve,
            'link' => $link,
            'affected_versions' => $this->extractAffectedVersions($vuln, $package),
        ];
    }

    /**
     * Build real affected-version constraints from the OSV record, limited to the
     * ranges that apply to the given Packagist package. Returns an empty array when
     * no parseable range is available (the advisory analyzer then fails open).
     *
     * @param  array<string, mixed>  $vuln
     * @return array<int, string>
     */
    private function extractAffectedVersions(array $vuln, string $package): array
    {
        if (! isset($vuln['affected']) || ! is_array($vuln['affected'])) {
            return [];
        }

        $constraints = [];

        foreach ($vuln['affected'] as $affected) {
            if (! is_array($affected) || ! $this->affectsPackage($affected, $package)) {
                continue;
            }

            $rangeConstraints = [];

            if (isset($affected['ranges']) && is_array($affected['ranges'])) {
                foreach ($affected['ranges'] as $range) {
                    if (! is_array($range)) {
                        continue;
                    }

                    foreach ($this->rangeToConstraints($range) as $constraint) {
                        $rangeConstraints[] = $constraint;
                    }
                }
            }

            if ($rangeConstraints !== []) {
                // Ranges (e.g. "<3.1.6") are the compact, triage-friendly form;
                // prefer them over OSV's often huge explicit version enumeration.
                foreach ($rangeConstraints as $constraint) {
                    $constraints[] = $constraint;
                }

                continue;
            }

            // Fall back to explicit affected versions only when no range is given.
            if (isset($affected['versions']) && is_array($affected['versions'])) {
                foreach ($affected['versions'] as $explicit) {
                    if (is_string($explicit) && $explicit !== '') {
                        $constraints[] = $explicit;
                    }
                }
            }
        }

        return array_values(array_unique($constraints));
    }

    /**
     * Whether an OSV "affected" entry applies to the given Packagist package. A
     * missing package block is treated as applicable (fail open); a present block
     * for another ecosystem/name (e.g. an npm alias of the same advisory) is not.
     *
     * @param  array<mixed, mixed>  $affected
     */
    private function affectsPackage(array $affected, string $package): bool
    {
        if (! isset($affected['package']) || ! is_array($affected['package'])) {
            return true;
        }

        $pkg = $affected['package'];

        $ecosystem = isset($pkg['ecosystem']) && is_string($pkg['ecosystem']) ? $pkg['ecosystem'] : null;
        if ($ecosystem !== null && strcasecmp($ecosystem, 'Packagist') !== 0) {
            return false;
        }

        $name = isset($pkg['name']) && is_string($pkg['name']) ? $pkg['name'] : null;
        if ($name !== null && strcasecmp($name, $package) !== 0) {
            return false;
        }

        return true;
    }

    /**
     * Convert one OSV range object into constraint strings. SEMVER/ECOSYSTEM
     * ranges are honoured; GIT ranges are ignored (not version-comparable).
     *
     * @param  array<mixed, mixed>  $range
     * @return array<int, string>
     */
    private function rangeToConstraints(array $range): array
    {
        $type = isset($range['type']) && is_string($range['type']) ? strtoupper($range['type']) : '';
        if ($type !== 'SEMVER' && $type !== 'ECOSYSTEM') {
            return [];
        }

        if (! isset($range['events']) || ! is_array($range['events'])) {
            return [];
        }

        $constraints = [];
        $introduced = null;

        foreach ($range['events'] as $event) {
            if (! is_array($event)) {
                continue;
            }

            if (isset($event['introduced']) && is_string($event['introduced'])) {
                $introduced = $event['introduced'];

                continue;
            }

            if (isset($event['fixed']) && is_string($event['fixed'])) {
                $constraints[] = $this->buildInterval($introduced, '<', $event['fixed']);
                $introduced = null;

                continue;
            }

            if (isset($event['last_affected']) && is_string($event['last_affected'])) {
                $constraints[] = $this->buildInterval($introduced, '<=', $event['last_affected']);
                $introduced = null;
            }
        }

        // Open-ended range: introduced with no closing fixed/last_affected event.
        if ($introduced !== null && $introduced !== '') {
            $constraints[] = $introduced === '0' ? '*' : '>='.$introduced;
        }

        return array_values(array_filter($constraints, static fn (string $c): bool => $c !== ''));
    }

    /**
     * Compose a constraint string for a single [introduced, upper) interval. A "0"
     * (or missing) lower bound is dropped, leaving just the upper bound.
     */
    private function buildInterval(?string $introduced, string $upperOperator, string $upper): string
    {
        if ($upper === '') {
            return '';
        }

        $upperConstraint = $upperOperator.$upper;

        if ($introduced === null || $introduced === '' || $introduced === '0') {
            return $upperConstraint;
        }

        return '>='.$introduced.','.$upperConstraint;
    }

    private function deriveVulnUrl(string $apiUrl): string
    {
        if (str_contains($apiUrl, 'querybatch')) {
            return str_replace('querybatch', 'vulns', $apiUrl);
        }

        return self::DEFAULT_VULN_SOURCE;
    }

    private function logFailure(Throwable $exception): void
    {
        if ($this->logger !== null) {
            $this->logger->warning('Failed to fetch security advisories: '.$exception->getMessage());
        }
    }
}
