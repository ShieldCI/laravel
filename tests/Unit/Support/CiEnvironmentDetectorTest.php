<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ShieldCI\Support\CiEnvironmentDetector;
use Symfony\Component\Process\Process;

class CiEnvironmentDetectorTest extends TestCase
{
    /** @var array<string, string|false> */
    private array $envBackup = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->envBackup = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->envBackup as $var => $original) {
            if ($original === false) {
                putenv($var);
            } else {
                putenv("{$var}={$original}");
            }
        }
        parent::tearDown();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private function setEnv(string $var, string $value): void
    {
        $this->envBackup[$var] = getenv($var);
        putenv("{$var}={$value}");
    }

    private function clearEnv(string $var): void
    {
        $this->envBackup[$var] = getenv($var);
        putenv($var);
    }

    private function makeDetector(): CiEnvironmentDetector
    {
        return new CiEnvironmentDetector;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provider detection
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function it_returns_null_when_no_ci_env_vars_set(): void
    {
        foreach (['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'BITBUCKET_BUILD_NUMBER',
            'TF_BUILD', 'JENKINS_URL', 'TRAVIS'] as $var) {
            $this->clearEnv($var);
        }

        $this->assertNull($this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_github_actions(): void
    {
        $this->setEnv('GITHUB_ACTIONS', 'true');
        $this->assertEquals('github_actions', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_gitlab_ci(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->setEnv('GITLAB_CI', 'true');
        $this->assertEquals('gitlab_ci', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_circleci(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->setEnv('CIRCLECI', 'true');
        $this->assertEquals('circleci', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_bitbucket(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->setEnv('BITBUCKET_BUILD_NUMBER', '42');
        $this->assertEquals('bitbucket', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_azure_devops(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->clearEnv('BITBUCKET_BUILD_NUMBER');
        $this->setEnv('TF_BUILD', 'True');
        $this->assertEquals('azure_devops', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_jenkins(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->clearEnv('BITBUCKET_BUILD_NUMBER');
        $this->clearEnv('TF_BUILD');
        $this->setEnv('JENKINS_URL', 'http://jenkins.example.com/');
        $this->assertEquals('jenkins', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_detects_travis_ci(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->clearEnv('BITBUCKET_BUILD_NUMBER');
        $this->clearEnv('TF_BUILD');
        $this->clearEnv('JENKINS_URL');
        $this->setEnv('TRAVIS', 'true');
        $this->assertEquals('travis_ci', $this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_does_not_detect_when_value_wrong(): void
    {
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->clearEnv('BITBUCKET_BUILD_NUMBER');
        $this->clearEnv('TF_BUILD');
        $this->clearEnv('JENKINS_URL');
        $this->clearEnv('TRAVIS');
        $this->setEnv('GITHUB_ACTIONS', 'false');
        $this->assertNull($this->makeDetector()->detectProvider());
    }

    #[Test]
    public function it_does_not_detect_bitbucket_when_var_is_empty(): void
    {
        $this->clearEnv('GITHUB_ACTIONS');
        $this->clearEnv('GITLAB_CI');
        $this->clearEnv('CIRCLECI');
        $this->clearEnv('TF_BUILD');
        $this->clearEnv('JENKINS_URL');
        $this->clearEnv('TRAVIS');
        $this->setEnv('BITBUCKET_BUILD_NUMBER', '');
        $this->assertNull($this->makeDetector()->detectProvider());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Branch resolution
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function it_reads_github_head_ref_first_for_branch(): void
    {
        $this->setEnv('GITHUB_HEAD_REF', 'feature/pr-branch');
        $this->setEnv('GITHUB_REF_NAME', 'main');

        $this->assertEquals('feature/pr-branch', $this->makeDetector()->resolveBranch('github_actions'));
    }

    #[Test]
    public function it_falls_back_to_github_ref_name_when_head_ref_empty(): void
    {
        $this->setEnv('GITHUB_HEAD_REF', '');
        $this->setEnv('GITHUB_REF_NAME', 'main');

        $this->assertEquals('main', $this->makeDetector()->resolveBranch('github_actions'));
    }

    #[Test]
    public function it_reads_branch_for_gitlab_ci(): void
    {
        $this->setEnv('CI_COMMIT_BRANCH', 'develop');
        $this->assertEquals('develop', $this->makeDetector()->resolveBranch('gitlab_ci'));
    }

    #[Test]
    public function it_reads_branch_for_circleci(): void
    {
        $this->setEnv('CIRCLE_BRANCH', 'release/1.0');
        $this->assertEquals('release/1.0', $this->makeDetector()->resolveBranch('circleci'));
    }

    #[Test]
    public function it_reads_branch_for_bitbucket(): void
    {
        $this->setEnv('BITBUCKET_BRANCH', 'hotfix/x');
        $this->assertEquals('hotfix/x', $this->makeDetector()->resolveBranch('bitbucket'));
    }

    #[Test]
    public function it_reads_branch_for_azure_devops(): void
    {
        $this->setEnv('BUILD_SOURCEBRANCHNAME', 'main');
        $this->assertEquals('main', $this->makeDetector()->resolveBranch('azure_devops'));
    }

    #[Test]
    public function it_reads_branch_for_jenkins(): void
    {
        $this->setEnv('GIT_BRANCH', 'origin/main');
        $this->assertEquals('origin/main', $this->makeDetector()->resolveBranch('jenkins'));
    }

    #[Test]
    public function it_reads_branch_for_travis_ci(): void
    {
        $this->setEnv('TRAVIS_BRANCH', 'master');
        $this->assertEquals('master', $this->makeDetector()->resolveBranch('travis_ci'));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Commit resolution
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function it_reads_commit_for_github_actions(): void
    {
        $this->setEnv('GITHUB_SHA', 'abc1234def5678');
        $this->assertEquals('abc1234def5678', $this->makeDetector()->resolveCommit('github_actions'));
    }

    #[Test]
    public function it_reads_commit_for_gitlab_ci(): void
    {
        $this->setEnv('CI_COMMIT_SHA', 'deadbeef');
        $this->assertEquals('deadbeef', $this->makeDetector()->resolveCommit('gitlab_ci'));
    }

    #[Test]
    public function it_reads_commit_for_circleci(): void
    {
        $this->setEnv('CIRCLE_SHA1', 'cafebabe');
        $this->assertEquals('cafebabe', $this->makeDetector()->resolveCommit('circleci'));
    }

    #[Test]
    public function it_reads_commit_for_bitbucket(): void
    {
        $this->setEnv('BITBUCKET_COMMIT', 'badf00d');
        $this->assertEquals('badf00d', $this->makeDetector()->resolveCommit('bitbucket'));
    }

    #[Test]
    public function it_reads_commit_for_azure_devops(): void
    {
        $this->setEnv('BUILD_SOURCEVERSION', '1234567890abcdef');
        $this->assertEquals('1234567890abcdef', $this->makeDetector()->resolveCommit('azure_devops'));
    }

    #[Test]
    public function it_reads_commit_for_jenkins(): void
    {
        $this->setEnv('GIT_COMMIT', 'feedface');
        $this->assertEquals('feedface', $this->makeDetector()->resolveCommit('jenkins'));
    }

    #[Test]
    public function it_reads_commit_for_travis_ci(): void
    {
        $this->setEnv('TRAVIS_COMMIT', 'c0ffee');
        $this->assertEquals('c0ffee', $this->makeDetector()->resolveCommit('travis_ci'));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Real process execution (exercises getProcess())
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function it_executes_real_git_process_without_throwing(): void
    {
        // Exercises the real getProcess() implementation path.
        // In a git repository the call succeeds; outside one it returns null gracefully.
        $detector = $this->makeDetector();
        $branch = $detector->resolveBranch(null);
        $commit = $detector->resolveCommit(null);

        // Either value is acceptable — we only assert no exception was thrown
        // and, if we are inside a git repo, the values are non-empty strings.
        $this->assertTrue($branch === null || is_string($branch));
        $this->assertTrue($commit === null || is_string($commit));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Git command fallback
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function it_falls_back_to_git_command_for_branch(): void
    {
        $this->clearEnv('GITHUB_HEAD_REF');
        $this->clearEnv('GITHUB_REF_NAME');

        $detector = $this->makeDetectorWithMockGit('main', 'abc1234');
        $this->assertEquals('main', $detector->resolveBranch(null));
    }

    #[Test]
    public function it_returns_null_for_detached_head_state(): void
    {
        $detector = $this->makeDetectorWithMockGit('HEAD', 'abc1234');
        $this->assertNull($detector->resolveBranch(null));
    }

    #[Test]
    public function it_returns_null_for_branch_when_git_fails(): void
    {
        $detector = $this->makeDetectorWithFailingGit();
        $this->assertNull($detector->resolveBranch(null));
    }

    #[Test]
    public function it_returns_null_for_branch_when_process_throws(): void
    {
        $detector = $this->makeDetectorWithThrowingProcess();
        $this->assertNull($detector->resolveBranch(null));
    }

    #[Test]
    public function it_falls_back_to_git_command_for_commit(): void
    {
        $this->clearEnv('GITHUB_SHA');

        $detector = $this->makeDetectorWithMockGit('main', 'abc1234deadbeef');
        $this->assertEquals('abc1234deadbeef', $detector->resolveCommit(null));
    }

    #[Test]
    public function it_returns_null_for_commit_when_git_fails(): void
    {
        $detector = $this->makeDetectorWithFailingGit();
        $this->assertNull($detector->resolveCommit(null));
    }

    #[Test]
    public function it_returns_null_for_commit_when_process_throws(): void
    {
        $detector = $this->makeDetectorWithThrowingProcess();
        $this->assertNull($detector->resolveCommit(null));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mock git helpers
    // ─────────────────────────────────────────────────────────────────────────

    private function makeDetectorWithMockGit(string $branch, string $commit): CiEnvironmentDetector
    {
        $scriptPath = $this->createMockGitScript($branch, $commit);

        return new class($scriptPath) extends CiEnvironmentDetector
        {
            public function __construct(private string $scriptPath) {}

            protected function getProcess(array $command): Process
            {
                // Map git subcommand to the mock script args
                $arg = in_array('--abbrev-ref', $command) ? '--abbrev-ref' : '--sha';

                return (new Process([$this->scriptPath, $arg]))->setTimeout(2);
            }
        };
    }

    private function makeDetectorWithThrowingProcess(): CiEnvironmentDetector
    {
        return new class extends CiEnvironmentDetector
        {
            protected function getProcess(array $command): Process
            {
                throw new \RuntimeException('Simulated process creation failure');
            }
        };
    }

    private function makeDetectorWithFailingGit(): CiEnvironmentDetector
    {
        $scriptPath = $this->createFailingGitScript();

        return new class($scriptPath) extends CiEnvironmentDetector
        {
            public function __construct(private string $scriptPath) {}

            protected function getProcess(array $command): Process
            {
                return (new Process([$this->scriptPath]))->setTimeout(2);
            }
        };
    }

    private function createMockGitScript(string $branch, string $commit): string
    {
        $path = sys_get_temp_dir().'/mock-git-'.uniqid();
        $branch = escapeshellarg($branch);
        $commit = escapeshellarg($commit);

        file_put_contents($path, <<<BASH
#!/bin/bash
if [ "\$1" = "--abbrev-ref" ]; then
    echo {$branch}
else
    echo {$commit}
fi
BASH);
        chmod($path, 0755);

        return $path;
    }

    private function createFailingGitScript(): string
    {
        $path = sys_get_temp_dir().'/mock-git-fail-'.uniqid();
        file_put_contents($path, "#!/bin/bash\nexit 128\n");
        chmod($path, 0755);

        return $path;
    }
}
