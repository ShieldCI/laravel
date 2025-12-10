<?php

declare(strict_types=1);

namespace ShieldCI\Support\SecurityAdvisories;

class AdvisoryAnalyzer implements AdvisoryAnalyzerInterface
{
    public function __construct(
        private VersionConstraintMatcher $matcher
    ) {
    }

    public function analyze(array $dependencies, array $advisories): array
    {
        $results = [];

        foreach ($dependencies as $package => $info) {
            if (! isset($advisories[$package]) || ! is_array($advisories[$package])) {
                continue;
            }

            $version = $info['version'] ?? null;
            if (! is_string($version)) {
                continue;
            }

            $matchedAdvisories = [];

            foreach ($advisories[$package] as $advisory) {
                if (! is_array($advisory)) {
                    continue;
                }

                $affectedSource = $advisory['affected_versions'] ?? $advisory['affectedVersions'] ?? [];
                if (is_array($affectedSource)) {
                    $affected = array_values(array_filter($affectedSource, 'is_string'));
                } elseif (is_string($affectedSource)) {
                    $affected = $affectedSource;
                } else {
                    $affected = [];
                }

                if (! $this->matcher->matches($version, $affected)) {
                    continue;
                }

                $matchedAdvisories[] = [
                    'title' => isset($advisory['title']) && is_string($advisory['title'])
                        ? $advisory['title']
                        : 'Known vulnerability',
                    'cve' => isset($advisory['cve']) && is_string($advisory['cve'])
                        ? $advisory['cve']
                        : null,
                    'link' => isset($advisory['link']) && is_string($advisory['link'])
                        ? $advisory['link']
                        : null,
                    'affected_versions' => $affected,
                ];
            }

            if (! empty($matchedAdvisories)) {
                $results[$package] = [
                    'version' => $version,
                    'advisories' => $matchedAdvisories,
                ];
            }
        }

        return $results;
    }
}
