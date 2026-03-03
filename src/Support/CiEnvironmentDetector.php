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
     * Resolve the pull-request / merge-request number from CI env vars.
     *
     * Returns null when not on a PR build or when the env var is absent.
     */
    public function resolvePrNumber(?string $provider): ?int
    {
        return match ($provider) {
            'github_actions' => $this->resolveNumericEnv('GITHUB_REF_NUMBER') ?? $this->parsePrFromGithubRef(),
            'gitlab_ci' => $this->resolveNumericEnv('CI_MERGE_REQUEST_IID'),
            'circleci' => $this->resolveNumericEnv('CIRCLE_PR_NUMBER'),
            'bitbucket' => $this->resolveNumericEnv('BITBUCKET_PR_ID'),
            'azure_devops' => $this->resolveNumericEnv('SYSTEM_PULLREQUEST_PULLREQUESTNUMBER'),
            'jenkins' => $this->resolveNumericEnv('CHANGE_ID'),
            'travis_ci' => $this->resolveTravisPrNumber(),
            default => null,
        };
    }

    /**
     * Resolve the repository in owner/repo format from CI env vars.
     *
     * Returns null when the format is unavailable for the provider.
     */
    public function resolveRepository(?string $provider): ?string
    {
        return match ($provider) {
            'github_actions' => $this->resolveNonEmptyEnv('GITHUB_REPOSITORY'),
            'gitlab_ci' => $this->resolveNonEmptyEnv('CI_PROJECT_PATH'),
            'circleci' => $this->resolveCircleCiRepository(),
            'bitbucket' => $this->resolveNonEmptyEnv('BITBUCKET_REPO_FULL_NAME'),
            'azure_devops' => null,
            'jenkins' => null,
            'travis_ci' => $this->resolveNonEmptyEnv('TRAVIS_REPO_SLUG'),
            default => null,
        };
    }

    /**
     * Resolve the PR target (base) branch from CI env vars.
     *
     * Returns null on non-PR builds (the env var is typically absent or empty).
     */
    public function resolveBaseBranch(?string $provider): ?string
    {
        return match ($provider) {
            'github_actions' => $this->resolveNonEmptyEnv('GITHUB_BASE_REF'),
            'gitlab_ci' => $this->resolveNonEmptyEnv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME'),
            'circleci' => null,
            'bitbucket' => $this->resolveNonEmptyEnv('BITBUCKET_PR_DESTINATION_BRANCH'),
            'azure_devops' => $this->resolveNonEmptyEnv('SYSTEM_PULLREQUEST_TARGETBRANCH'),
            'jenkins' => $this->resolveNonEmptyEnv('CHANGE_TARGET'),
            'travis_ci' => $this->resolveTravisBaseBranch(),
            default => null,
        };
    }

    /**
     * Read an env var and cast it to int if numeric, otherwise return null.
     */
    private function resolveNumericEnv(string $var): ?int
    {
        $value = getenv($var);
        if (! is_string($value) || $value === '') {
            return null;
        }

        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * Read an env var and return its value if non-empty, otherwise null.
     */
    private function resolveNonEmptyEnv(string $var): ?string
    {
        $value = getenv($var);

        return (is_string($value) && $value !== '') ? $value : null;
    }

    /**
     * Parse the PR number from GITHUB_REF (e.g. refs/pull/42/merge).
     */
    private function parsePrFromGithubRef(): ?int
    {
        $ref = getenv('GITHUB_REF');
        if (! is_string($ref) || $ref === '') {
            return null;
        }

        if (preg_match('#^refs/pull/(\d+)/#', $ref, $matches)) {
            return (int) $matches[1];
        }

        return null;
    }

    /**
     * Resolve PR number for Travis CI (TRAVIS_PULL_REQUEST is 'false' on non-PR builds).
     */
    private function resolveTravisPrNumber(): ?int
    {
        $value = getenv('TRAVIS_PULL_REQUEST');
        if (! is_string($value) || $value === '' || $value === 'false') {
            return null;
        }

        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * Resolve repository in owner/repo format for CircleCI.
     */
    private function resolveCircleCiRepository(): ?string
    {
        $username = getenv('CIRCLE_PROJECT_USERNAME');
        $reponame = getenv('CIRCLE_PROJECT_REPONAME');

        if (! is_string($username) || $username === '' || ! is_string($reponame) || $reponame === '') {
            return null;
        }

        return $username.'/'.$reponame;
    }

    /**
     * Resolve base branch for Travis CI (only available on PR builds).
     */
    private function resolveTravisBaseBranch(): ?string
    {
        $pr = getenv('TRAVIS_PULL_REQUEST');
        if (! is_string($pr) || $pr === '' || $pr === 'false') {
            return null;
        }

        return $this->resolveNonEmptyEnv('TRAVIS_BRANCH');
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
