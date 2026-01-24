<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\HardcodedStoragePathsAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class HardcodedStoragePathsAnalyzerTest extends AnalyzerTestCase
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function createAnalyzer(array $config = []): AnalyzerInterface
    {
        $configRepo = new Repository([
            'shieldci' => [
                'analyzers' => [
                    'best-practices' => $config,
                ],
            ],
        ]);

        return new HardcodedStoragePathsAnalyzer($this->parser, $configRepo);
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

    public function test_skips_urls_as_false_positives(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ApiService
{
    public function getApiUrl()
    {
        return 'https://example.com/storage/app/files/document.pdf';
    }

    public function getSecureUrl()
    {
        return 'http://cdn.example.com/public/images/logo.jpg';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ApiService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_windows_storage_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class WindowsFileService
{
    public function getPath()
    {
        return 'C:\storage\app\uploads\file.jpg';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WindowsFileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('storage', $result);
    }

    public function test_detects_windows_public_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class WindowsPublicService
{
    public function getPublicPath()
    {
        return 'D:\public\uploads\avatar.png';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/WindowsPublicService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('public', $result);
    }

    public function test_detects_relative_storage_paths(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class RelativePathService
{
    public function getPath()
    {
        return '../storage/app/files/data.json';
    }

    public function getPublicPath()
    {
        return './public/images/icon.svg';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/RelativePathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertCount(2, $issues);
    }

    public function test_detects_app_path_hardcoding(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class AppPathService
{
    public function getAppPath()
    {
        return '/var/www/app/Models/User.php';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/AppPathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('app_path', $issues[0]->recommendation);
    }

    public function test_detects_resource_path_hardcoding(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ResourceService
{
    public function getViewPath()
    {
        return '/var/www/resources/views/home.blade.php';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ResourceService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('resource_path', $issues[0]->recommendation);
    }

    public function test_detects_database_path_hardcoding(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DatabaseService
{
    public function getMigrationPath()
    {
        return '/var/www/database/migrations/2023_create_users_table.php';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DatabaseService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('database_path', $issues[0]->recommendation);
    }

    public function test_detects_config_path_hardcoding(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getConfigPath()
    {
        return '/var/www/config/app.php';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('config_path', $issues[0]->recommendation);
    }

    public function test_detects_heredoc_hardcoded_paths(): void
    {
        // Use ../storage/ which is an "always flag" pattern (relative path)
        $code = <<<'PHP'
<?php

namespace App\Services;

class HeredocService
{
    public function getPath()
    {
        $path = <<<'EOT'
../storage/app/files/data.json
EOT;
        return $path;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/HeredocService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('storage', $result);
    }

    public function test_detects_multiple_hardcoded_paths_in_same_file(): void
    {
        // Use relative paths (./ and ../) which are "always flag" patterns
        $code = <<<'PHP'
<?php

namespace App\Services;

class MultiPathService
{
    public function getStoragePath()
    {
        return '../storage/app/files/data.json';
    }

    public function getPublicPath()
    {
        return './public/images/logo.png';
    }

    public function getLogPath()
    {
        return '../storage/logs/app.log';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/MultiPathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    public function test_respects_allowed_paths_configuration(): void
    {
        // Use relative paths so they're "always flag" patterns, then test allowed_paths works
        $code = <<<'PHP'
<?php

namespace App\Services;

class OAuthService
{
    public function getPublicKeyPath()
    {
        return '../storage/oauth-public.key';
    }

    public function getPrivateKeyPath()
    {
        return '../storage/oauth-private.key';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/OAuthService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'hardcoded-storage-paths' => [
                'allowed_paths' => [
                    '../storage/oauth-public.key',
                    '../storage/oauth-private.key',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_respects_additional_patterns_configuration(): void
    {
        // Additional patterns are added to "always flag" patterns, so they work regardless of context
        $code = <<<'PHP'
<?php

namespace App\Services;

class CustomPathService
{
    public function getCustomPath()
    {
        return '/custom/uploads/file.jpg';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/CustomPathService.php' => $code]);

        $analyzer = $this->createAnalyzer([
            'hardcoded-storage-paths' => [
                'additional_patterns' => [
                    '/\/custom\/uploads\//i' => 'custom_upload_path(...)',
                ],
            ],
        ]);
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertStringContainsString('custom_upload_path', $issues[0]->recommendation);
    }

    public function test_detects_paths_in_array_literals(): void
    {
        // Use relative paths (./) which are "always flag" patterns
        $code = <<<'PHP'
<?php

namespace App\Services;

class ArrayPathService
{
    public function getConfig()
    {
        return [
            'upload_path' => './storage/app/uploads',
            'image_path' => './public/images',
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ArrayPathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_detects_paths_in_class_constants(): void
    {
        // Use relative paths (../) which are "always flag" patterns
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConstantPathService
{
    const UPLOAD_DIR = '../storage/app/uploads';
    const PUBLIC_DIR = '../public/assets';
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConstantPathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_detects_paths_as_function_arguments(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FunctionArgService
{
    public function checkFile()
    {
        if (file_exists('/storage/app/file.jpg')) {
            return true;
        }
        return false;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FunctionArgService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('storage', $result);
    }

    public function test_handles_empty_files(): void
    {
        $code = <<<'PHP'
<?php
PHP;

        $tempDir = $this->createTempDirectory(['Empty.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_handles_files_with_only_comments(): void
    {
        $code = <<<'PHP'
<?php

// This is just a comment
// Another comment
/* Block comment */
PHP;

        $tempDir = $this->createTempDirectory(['Comments.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_long_paths(): void
    {
        // Use relative path (../) which is an "always flag" pattern
        $longPath = '../storage/app/very/deep/nested/path/to/files/'.str_repeat('subfolder/', 50).'file.jpg';
        $code = <<<PHP
<?php

namespace App\Services;

class LongPathService
{
    public function getLongPath()
    {
        return '$longPath';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LongPathService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
    }

    // =========================================================================
    // Context-Aware Detection Tests (False Positive Prevention)
    // =========================================================================

    public function test_ignores_route_definitions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Routes;

use Illuminate\Support\Facades\Route;

Route::get('/app/dashboard', fn() => view('dashboard'));
Route::post('/storage/upload', [UploadController::class, 'store']);
Route::get('/public/profile', [ProfileController::class, 'show']);
Route::get('/resources/files', [ResourceController::class, 'index']);
PHP;

        $tempDir = $this->createTempDirectory(['routes/web.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_ignores_asset_urls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AvatarController
{
    public function show()
    {
        $avatarPath = '/storage/avatars/user.jpg';
        $imagePath = '/public/images/logo.png';
        $resourcePath = '/resources/icons/star.svg';

        return view('profile', compact('avatarPath', 'imagePath', 'resourcePath'));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Controllers/AvatarController.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        // These are just strings in variables, not filesystem operations
        $this->assertPassed($result);
    }

    public function test_ignores_test_assertions(): void
    {
        $code = <<<'PHP'
<?php

namespace Tests\Feature;

use Tests\TestCase;

class DashboardTest extends TestCase
{
    public function test_user_can_access_dashboard(): void
    {
        $response = $this->get('/app/dashboard');
        $response->assertStatus(200);
    }

    public function test_redirect_to_storage(): void
    {
        $response = $this->post('/upload');
        $response->assertRedirect('/storage/files');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['tests/DashboardTest.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_paths_in_filesystem_functions(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FileService
{
    public function readFile()
    {
        return file_get_contents('/storage/app/data.json');
    }

    public function checkExists()
    {
        return file_exists('/public/uploads/file.txt');
    }

    public function openFile()
    {
        return fopen('/app/cache/temp.txt', 'r');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    public function test_detects_paths_in_laravel_file_facade(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;

class LaravelFileService
{
    public function readWithFile()
    {
        return File::get('/storage/app/config.json');
    }

    public function existsWithFile()
    {
        return File::exists('/public/images/logo.png');
    }

    public function storagePath()
    {
        return Storage::path('/app/uploads');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/LaravelFileService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(3, count($issues));
    }

    public function test_always_flags_var_www_paths_regardless_of_context(): void
    {
        // /var/www/ paths should ALWAYS be flagged, even outside filesystem context
        $code = <<<'PHP'
<?php

namespace App\Services;

class ConfigService
{
    public function getPath()
    {
        return '/var/www/html/storage/app/data.json';
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/ConfigService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('storage', $result);
    }

    public function test_nested_function_calls_detected(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class JsonService
{
    public function loadConfig()
    {
        return json_decode(file_get_contents('/storage/app/config.json'), true);
    }

    public function saveData($data)
    {
        file_put_contents('/public/data/output.json', json_encode($data));
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/JsonService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_detects_paths_in_mkdir(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class DirectoryService
{
    public function createUploadDir()
    {
        mkdir('/storage/app/uploads', 0755, true);
    }

    public function scanDir()
    {
        return scandir('/public/images');
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/DirectoryService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_detects_paths_in_instance_methods(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class FilesystemService
{
    public function __construct(private $filesystem) {}

    public function readFile()
    {
        return $this->filesystem->get('/storage/app/file.txt');
    }

    public function writeFile($content)
    {
        $this->filesystem->put('/public/data/output.txt', $content);
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['Services/FilesystemService.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }
}
