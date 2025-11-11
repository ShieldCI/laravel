<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\HardcodedStoragePathsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HardcodedStoragePathsAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new HardcodedStoragePathsAnalyzer($this->parser);
    }

    public function test_passes_with_storage_path_helper(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function saveLogo($file)
    {
        $path = storage_path('app/public/logos');
        $file->move($path, 'logo.png');
    }

    public function getLogPath()
    {
        return storage_path('logs/app.log');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_hardcoded_storage_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ImageService
{
    public function saveImage($file)
    {
        $path = '/var/www/html/storage/app/public/images';
        $file->move($path, 'image.jpg');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ImageService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('storage', $result);
    }

    public function test_detects_hardcoded_public_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AssetService
{
    public function getImagePath()
    {
        return '/var/www/public/images/banner.jpg';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AssetService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_detects_hardcoded_log_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class LogService
{
    public function writeLog($message)
    {
        file_put_contents('/var/www/storage/logs/custom.log', $message);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LogService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    public function test_provides_helper_recommendation(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class UploadService
{
    public function upload()
    {
        $path = '/var/www/storage/app/uploads';
        // Upload file
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/UploadService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThan(0, count($issues));
        $this->assertStringContainsString('storage_path', $issues[0]->recommendation);
    }

    public function test_ignores_files_with_parse_errors(): void
    {
        $code = '<?php this is invalid PHP code {{{';

        $tempDir = $this->createTempDirectory(['Invalid.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
