<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\Security;

use ShieldCI\Analyzers\Security\XssAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class XssAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new XssAnalyzer;
    }

    public function test_passes_with_escaped_blade_output(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <h1>{{ $title }}</h1>
    <p>{{ $user->name }}</p>
    <div>{{ request('search') }}</div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['welcome.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_unescaped_blade_output_with_user_input(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    <h1>{!! $title !!}</h1>
    <div>{!! request('content') !!}</div>
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['page.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Unescaped blade output', $result);
    }

    public function test_detects_echo_with_superglobals(): void
    {
        $phpCode = <<<'PHP'
<?php

class ViewController
{
    public function display()
    {
        echo $_GET['message'];
        echo $_POST['content'];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ViewController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Direct echo of superglobal', $result);
        $this->assertIssueCount(2, $result);
    }

    public function test_detects_echo_with_request_helper(): void
    {
        $phpCode = <<<'PHP'
<?php

class PageController
{
    public function show()
    {
        echo request('title');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['PageController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Echo of request data', $result);
    }

    public function test_passes_with_escaped_echo(): void
    {
        $phpCode = <<<'PHP'
<?php

class SafeController
{
    public function display()
    {
        echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
        echo e(request('title'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['SafeController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_response_make_with_user_input(): void
    {
        $phpCode = <<<'PHP'
<?php

class ApiController
{
    public function render()
    {
        return Response::make(request('html'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['ApiController.php' => $phpCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Response::make()', $result);
    }

    public function test_detects_user_data_in_javascript(): void
    {
        $bladeCode = <<<'BLADE'
<script>
    var username = '{{ $user->name }}';
    var searchQuery = @json($request->get('search'));
    var data = {{ $_GET['data'] }};
</script>
BLADE;

        $tempDir = $this->createTempDirectory(['script.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('User data in JavaScript', $result);
    }

    public function test_allows_unescaped_output_for_safe_html(): void
    {
        $bladeCode = <<<'BLADE'
<div>
    {!! $safeHtml !!}
    {!! $content !!}
</div>
BLADE;

        $tempDir = $this->createTempDirectory(['content.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // Should pass because variable names don't indicate user input
        $this->assertPassed($result);
    }

    public function test_detects_multiple_xss_vulnerabilities(): void
    {
        $bladeCode = <<<'BLADE'
<html>
<head>
    <script>
        var query = {{ $_GET['q'] }};
    </script>
</head>
<body>
    <h1>{!! request('title') !!}</h1>
    <div><?php echo $_POST['content']; ?></div>
</body>
</html>
BLADE;

        $tempDir = $this->createTempDirectory(['vulnerable.blade.php' => $bladeCode]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertGreaterThanOrEqual(3, count($result->getIssues()));
    }

    public function test_scans_both_php_and_blade_files(): void
    {
        $phpCode = <<<'PHP'
<?php
class TestController {
    public function index() {
        echo $_GET['test'];
    }
}
PHP;

        $bladeCode = <<<'BLADE'
<div>{!! request('data') !!}</div>
BLADE;

        $tempDir = $this->createTempDirectory([
            'TestController.php' => $phpCode,
            'test.blade.php' => $bladeCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        // Should detect both issues (may detect more than 2)
        $this->assertGreaterThanOrEqual(2, count($result->getIssues()));
    }
}
