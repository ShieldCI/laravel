<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use ShieldCI\AnalyzersCore\Support\PlatformDetector;

/**
 * Provides Vapor/serverless platform detection with test-override support.
 */
trait DetectsDeploymentPlatform
{
    private ?string $deploymentPlatformOverride = null;

    /**
     * Override deployment platform detection (testing only).
     */
    public function setDeploymentPlatform(string $platform): void
    {
        $this->deploymentPlatformOverride = $platform;
    }

    private function isVaporOrServerless(): bool
    {
        if ($this->deploymentPlatformOverride !== null) {
            return in_array($this->deploymentPlatformOverride, ['vapor', 'serverless'], true);
        }

        return PlatformDetector::isLaravelVapor($this->getBasePath())
            || PlatformDetector::isServerless();
    }
}
