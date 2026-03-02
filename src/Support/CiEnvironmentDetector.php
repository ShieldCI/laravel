<?php

declare(strict_types=1);

namespace ShieldCI\Support;

use Symfony\Component\Process\Process;

/**
 * Detects the CI provider and resolves git branch/commit from environment variables.
 *
 * Priority chain for branch and commit:
 *   1. CI provider env vars (when running in a known CI system)
 *   2. git shell command fallback (when running locally or in unknown CI)
 */
class CiEnvironmentDetector
{
    /**
     * Ordered list of CI providers. First match wins.
     *
     * @var array<string, array{var: string, value: string|null}>
     */
    private const PROVIDERS = [
        'github_actions' => ['var' => 'GITHUB_ACTIONS', 'value' => 'true'],
        'gitlab_ci' => ['var' => 'GITLAB_CI', 'value' => 'true'],
        'circleci' => ['var' => 'CIRCLECI', 'value' => 'true'],
        'bitbucket' => ['var' => 'BITBUCKET_BUILD_NUMBER', 'value' => null],
        'azure_devops' => ['var' => 'TF_BUILD', 'value' => 'True'],
        'jenkins' => ['var' => 'JENKINS_URL', 'value' => null],
        'travis_ci' => ['var' => 'TRAVIS', 'value' => 'true'],
    ];

    /**
     * Branch env vars per provider. First non-empty wins within platform.
     *
     * @var array<string, array<int, string>>
     */
    private const BRANCH_VARS = [
        'github_actions' => ['GITHUB_HEAD_REF', 'GITHUB_REF_NAME'],
        'gitlab_ci' => ['CI_COMMIT_BRANCH'],
        'circleci' => ['CIRCLE_BRANCH'],
        'bitbucket' => ['BITBUCKET_BRANCH'],
        'azure_devops' => ['BUILD_SOURCEBRANCHNAME'],
        'jenkins' => ['GIT_BRANCH'],
        'travis_ci' => ['TRAVIS_BRANCH'],
    ];

    /**
     * Commit env vars per provider (single var each).
     *
     * @var array<string, string>
     */
    private const COMMIT_VARS = [
        'github_actions' => 'GITHUB_SHA',
        'gitlab_ci' => 'CI_COMMIT_SHA',
        'circleci' => 'CIRCLE_SHA1',
        'bitbucket' => 'BITBUCKET_COMMIT',
        'azure_devops' => 'BUILD_SOURCEVERSION',
        'jenkins' => 'GIT_COMMIT',
        'travis_ci' => 'TRAVIS_COMMIT',
    ];

    /**
     * Detect the current CI provider.
     *
     * Returns null when running locally or in an unrecognised CI system.
     */
    public function detectProvider(): ?string
    {
        foreach (self::PROVIDERS as $key => $spec) {
            $actual = getenv($spec['var']);

            if ($spec['value'] === null) {
                // Presence check: env var must be non-empty
                if (is_string($actual) && $actual !== '') {
                    return $key;
                }
            } else {
                // Exact value match
                if ($actual === $spec['value']) {
                    return $key;
                }
            }
        }

        return null;
    }

    /**
     * Resolve the git branch.
     *
     * When a $provider is given, reads the provider-specific env var first.
     * Falls back to `git rev-parse --abbrev-ref HEAD` when no env var resolves the value.
     */
    public function resolveBranch(?string $provider): ?string
    {
        if ($provider !== null && isset(self::BRANCH_VARS[$provider])) {
            foreach (self::BRANCH_VARS[$provider] as $var) {
                $value = getenv($var);
                if (is_string($value) && $value !== '') {
                    return $value;
                }
            }
        }

        return $this->runGitCommand(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 'HEAD');
    }

    /**
     * Resolve the git commit SHA.
     *
     * When a $provider is given, reads the provider-specific env var first.
     * Falls back to `git rev-parse HEAD` when no env var resolves the value.
     */
    public function resolveCommit(?string $provider): ?string
    {
        if ($provider !== null && isset(self::COMMIT_VARS[$provider])) {
            $value = getenv(self::COMMIT_VARS[$provider]);
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return $this->runGitCommand(['git', 'rev-parse', 'HEAD'], null);
    }

    /**
     * Run a git command and return trimmed stdout, or null on failure.
     *
     * @param  array<int, string>  $command
     */
    private function runGitCommand(array $command, ?string $nullIfOutput): ?string
    {
        try {
            $process = $this->getProcess($command);
            $process->run();

            if (! $process->isSuccessful()) {
                return null;
            }

            $output = trim($process->getOutput());
            if ($output === '' || $output === $nullIfOutput) {
                return null;
            }

            return $output;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Get a new Symfony Process instance.
     *
     * Overridable in tests to inject mock git scripts.
     *
     * @param  array<int, string>  $command
     */
    protected function getProcess(array $command): Process
    {
        return (new Process($command))->setTimeout(2);
    }
}
