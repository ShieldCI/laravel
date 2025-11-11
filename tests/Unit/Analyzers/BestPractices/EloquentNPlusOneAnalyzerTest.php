<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
    }

    public function test_detects_n_plus_one_queries(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('N+1', $result);
    }

    public function test_passes_with_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with(['user', 'comments'])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }
}
