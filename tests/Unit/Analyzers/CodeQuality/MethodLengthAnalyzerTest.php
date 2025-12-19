<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\CodeQuality;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\Test;
use ShieldCI\Analyzers\CodeQuality\MethodLengthAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\Tests\AnalyzerTestCase;

class MethodLengthAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'code-quality' => $config,
                ],
            ],
        ]);

        return new MethodLengthAnalyzer($this->parser, $configRepo);
    }

    #[Test]
    public function test_detects_long_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataProcessor
{
    public function processData(\$input)
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataProcessor.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('lines', $result);
    }

    #[Test]
    public function test_passes_with_short_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UserService
{
    public function getName($user)
    {
        return $user->name ?? 'Unknown';
    }

    public function getEmail($user)
    {
        return $user->email;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/UserService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_getter_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataService
{
    // Getter should be excluded even if long
    public function getData()
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because getters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_setter_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class DataService
{
    // Setter should be excluded even if long
    public function setConfiguration(\$config)
    {
{$statements}
        return \$var;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/DataService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because setters are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_is_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class ValidationService
{
    // is* methods should be excluded even if long
    public function isValid(\$data)
    {
{$statements}
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/ValidationService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because is* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_excludes_has_methods(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class FeatureService
{
    // has* methods should be excluded even if long
    public function hasPermission(\$user)
    {
{$statements}
        return true;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/FeatureService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because has* methods are excluded
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_at_exact_threshold_passes(): void
    {
        // Exactly 50 statements (at threshold, not over)
        $statements = str_repeat('        $var = "value";'."\n", 50);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because we're at threshold, not over
        $this->assertPassed($result);
    }

    #[Test]
    public function test_method_at_threshold_plus_one_fails(): void
    {
        // 51 statements (threshold + 1)
        $statements = str_repeat('        $var = "value";'."\n", 51);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail because we're over threshold
        $this->assertFailed($result);
    }

    #[Test]
    public function test_severity_is_low_for_moderate_length(): void
    {
        // 60 lines (1.2x threshold)
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Low, $issues[0]->severity);
    }

    #[Test]
    public function test_severity_is_medium_for_excessive_length(): void
    {
        // 100 lines (2x threshold)
        $statements = str_repeat('        $var = "value";'."\n", 100);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::Medium, $issues[0]->severity);
    }

    #[Test]
    public function test_detects_long_standalone_functions(): void
    {
        $statements = str_repeat('    $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Helpers;

function processHelper(\$data)
{
{$statements}
    return \$var;
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Helpers/helpers.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('processHelper', $result);
    }

    #[Test]
    public function test_counts_nested_if_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($data)
    {
        if ($data > 0) {
            $a = 1;
            $b = 2;
            $c = 3;
            if ($data > 10) {
                $d = 4;
                $e = 5;
                $f = 6;
            } else {
                $g = 7;
                $h = 8;
            }
        }
        // Add statements to exceed threshold
        $s1 = 1; $s2 = 2; $s3 = 3; $s4 = 4; $s5 = 5;
        $s6 = 6; $s7 = 7; $s8 = 8; $s9 = 9; $s10 = 10;
        $s11 = 11; $s12 = 12; $s13 = 13; $s14 = 14; $s15 = 15;
        $s16 = 16; $s17 = 17; $s18 = 18; $s19 = 19; $s20 = 20;
        $s21 = 21; $s22 = 22; $s23 = 23; $s24 = 24; $s25 = 25;
        $s26 = 26; $s27 = 27; $s28 = 28; $s29 = 29; $s30 = 30;
        $s31 = 31; $s32 = 32; $s33 = 33; $s34 = 34; $s35 = 35;
        $s36 = 36; $s37 = 37; $s38 = 38; $s39 = 39; $s40 = 40;
        $s41 = 41; $s42 = 42; $s43 = 43; $s44 = 44; $s45 = 45;
        $s46 = 46; $s47 = 47; $s48 = 48; $s49 = 49; $s50 = 50;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_counts_foreach_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($items)
    {
        foreach ($items as $item) {
            $a = 1;
            $b = 2;
            $c = 3;
        }
        // Total: 1 (foreach) + 3 (a,b,c) = 4 statements
        // Need 47+ more to exceed threshold
        $s1 = 1; $s2 = 2; $s3 = 3; $s4 = 4; $s5 = 5;
        $s6 = 6; $s7 = 7; $s8 = 8; $s9 = 9; $s10 = 10;
        $s11 = 11; $s12 = 12; $s13 = 13; $s14 = 14; $s15 = 15;
        $s16 = 16; $s17 = 17; $s18 = 18; $s19 = 19; $s20 = 20;
        $s21 = 21; $s22 = 22; $s23 = 23; $s24 = 24; $s25 = 25;
        $s26 = 26; $s27 = 27; $s28 = 28; $s29 = 29; $s30 = 30;
        $s31 = 31; $s32 = 32; $s33 = 33; $s34 = 34; $s35 = 35;
        $s36 = 36; $s37 = 37; $s38 = 38; $s39 = 39; $s40 = 40;
        $s41 = 41; $s42 = 42; $s43 = 43; $s44 = 44; $s45 = 45;
        $s46 = 46; $s47 = 47;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_counts_while_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($condition)
    {
        while ($condition) {
            $a = 1;
            $b = 2;
            $c = 3;
        }
        // Total: 1 (while) + 3 (a,b,c) = 4 statements
        // Need 47+ more to exceed threshold
        $s1 = 1; $s2 = 2; $s3 = 3; $s4 = 4; $s5 = 5;
        $s6 = 6; $s7 = 7; $s8 = 8; $s9 = 9; $s10 = 10;
        $s11 = 11; $s12 = 12; $s13 = 13; $s14 = 14; $s15 = 15;
        $s16 = 16; $s17 = 17; $s18 = 18; $s19 = 19; $s20 = 20;
        $s21 = 21; $s22 = 22; $s23 = 23; $s24 = 24; $s25 = 25;
        $s26 = 26; $s27 = 27; $s28 = 28; $s29 = 29; $s30 = 30;
        $s31 = 31; $s32 = 32; $s33 = 33; $s34 = 34; $s35 = 35;
        $s36 = 36; $s37 = 37; $s38 = 38; $s39 = 39; $s40 = 40;
        $s41 = 41; $s42 = 42; $s43 = 43; $s44 = 44; $s45 = 45;
        $s46 = 46; $s47 = 47;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_counts_switch_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process($value)
    {
        switch ($value) {
            case 1:
                $a = 1;
                $b = 2;
                break;
            case 2:
                $c = 3;
                $d = 4;
                break;
            default:
                $e = 5;
        }
        // Total: 1 (switch) + 3 (a,b,break) + 3 (c,d,break) + 1 (e) = 8 statements
        // Need 43+ more to exceed threshold
        $s1 = 1; $s2 = 2; $s3 = 3; $s4 = 4; $s5 = 5;
        $s6 = 6; $s7 = 7; $s8 = 8; $s9 = 9; $s10 = 10;
        $s11 = 11; $s12 = 12; $s13 = 13; $s14 = 14; $s15 = 15;
        $s16 = 16; $s17 = 17; $s18 = 18; $s19 = 19; $s20 = 20;
        $s21 = 21; $s22 = 22; $s23 = 23; $s24 = 24; $s25 = 25;
        $s26 = 26; $s27 = 27; $s28 = 28; $s29 = 29; $s30 = 30;
        $s31 = 31; $s32 = 32; $s33 = 33; $s34 = 34; $s35 = 35;
        $s36 = 36; $s37 = 37; $s38 = 38; $s39 = 39; $s40 = 40;
        $s41 = 41; $s42 = 42; $s43 = 43;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_counts_try_catch_statements(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class Service
{
    public function process()
    {
        try {
            $a = 1;
            $b = 2;
            $c = 3;
        } catch (\Exception $e) {
            $d = 4;
            $e = 5;
        } finally {
            $f = 6;
        }
        // Add statements to exceed threshold
        $s1 = 1; $s2 = 2; $s3 = 3; $s4 = 4; $s5 = 5;
        $s6 = 6; $s7 = 7; $s8 = 8; $s9 = 9; $s10 = 10;
        $s11 = 11; $s12 = 12; $s13 = 13; $s14 = 14; $s15 = 15;
        $s16 = 16; $s17 = 17; $s18 = 18; $s19 = 19; $s20 = 20;
        $s21 = 21; $s22 = 22; $s23 = 23; $s24 = 24; $s25 = 25;
        $s26 = 26; $s27 = 27; $s28 = 28; $s29 = 29; $s30 = 30;
        $s31 = 31; $s32 = 32; $s33 = 33; $s34 = 34; $s35 = 35;
        $s36 = 36; $s37 = 37; $s38 = 38; $s39 = 39; $s40 = 40;
        $s41 = 41; $s42 = 42; $s43 = 43; $s44 = 44; $s45 = 45;
        $s46 = 46; $s47 = 47; $s48 = 48; $s49 = 49; $s50 = 50;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    #[Test]
    public function test_handles_abstract_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

abstract class BaseService
{
    // Abstract method has no body, should not be flagged
    abstract public function process($data);

    public function helper()
    {
        return 'test';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/BaseService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass because abstract method has no statements
        $this->assertPassed($result);
    }

    #[Test]
    public function test_detects_multiple_long_methods_in_one_file(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function firstMethod()
    {
{$statements}
        return \$var;
    }

    public function secondMethod()
    {
{$statements}
        return \$var;
    }

    public function shortMethod()
    {
        return 'short';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
        $this->assertHasIssueContaining('firstMethod', $result);
        $this->assertHasIssueContaining('secondMethod', $result);
    }

    #[Test]
    public function test_includes_correct_metadata(): void
    {
        $statements = str_repeat('        $var = "value";'."\n", 60);

        $code = <<<PHP
<?php

namespace App\Services;

class Service
{
    public function process()
    {
{$statements}
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Service.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);

        $metadata = $issues[0]->metadata;
        $this->assertArrayHasKey('method', $metadata);
        $this->assertArrayHasKey('lines', $metadata);
        $this->assertArrayHasKey('threshold', $metadata);
        $this->assertSame('process', $metadata['method']);
        $this->assertSame(50, $metadata['threshold']);
    }

    #[Test]
    public function test_has_correct_analyzer_metadata(): void
    {
        $analyzer = $this->createAnalyzer();
        $metadata = $analyzer->getMetadata();

        $this->assertSame('method-length', $metadata->id);
        $this->assertSame('Method Length Analyzer', $metadata->name);
        $this->assertContains('maintainability', $metadata->tags);
    }
}
