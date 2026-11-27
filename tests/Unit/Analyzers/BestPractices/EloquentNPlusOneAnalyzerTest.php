<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use PhpParser\NodeTraverser;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\AccessorRegistry;
use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\Analyzers\BestPractices\ModelAttributesRegistry;
use ShieldCI\Analyzers\BestPractices\ModelScanResult;
use ShieldCI\Analyzers\BestPractices\NPlusOneVisitor;
use ShieldCI\Analyzers\BestPractices\RelationshipRegistry;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneAnalyzerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
    }

    public function test_seeded_binding_flags_lazy_relation_in_a_loop(): void
    {
        // Force-load EloquentNPlusOneAnalyzer.php: ModelScanResult, RelationshipRegistry, etc.
        // live in that file but aren't individually PSR-4 addressable, so referencing them
        // directly (without ever instantiating the analyzer) needs an explicit autoload nudge.
        class_exists(EloquentNPlusOneAnalyzer::class);

        // A view-shaped snippet: $cities has no query assignment here — its type/eager-loads
        // must come from the seed, exactly as a Blade template would receive them.
        $code = <<<'PHP'
        <?php
        foreach ($cities as $city) {
            echo $city->airports->count();
        }
        PHP;

        $ast = (new AstParser)->parseCode($code);
        $scanResult = new ModelScanResult(new RelationshipRegistry, new ModelAttributesRegistry, new AccessorRegistry);
        // Register 'airports' as a real relationship on City so registry lookup succeeds.
        $scanResult->relationships->add('City', 'airports');

        $visitor = new NPlusOneVisitor($scanResult, [
            'cities' => ['type' => 'Collection<City>', 'eagerLoads' => []],
        ]);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $this->assertNotEmpty($visitor->getIssues());
        $this->assertSame('airports', $visitor->getIssues()[0]['relationship']);
    }

    public function test_seeded_eager_load_suppresses_the_finding(): void
    {
        class_exists(EloquentNPlusOneAnalyzer::class);

        $code = <<<'PHP'
        <?php
        foreach ($cities as $city) {
            echo $city->airports->count();
        }
        PHP;

        $ast = (new AstParser)->parseCode($code);
        $scanResult = new ModelScanResult(new RelationshipRegistry, new ModelAttributesRegistry, new AccessorRegistry);
        $scanResult->relationships->add('City', 'airports');

        $visitor = new NPlusOneVisitor($scanResult, [
            'cities' => ['type' => 'Collection<City>', 'eagerLoads' => ['airports']],
        ]);
        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $this->assertSame([], $visitor->getIssues());
    }

    public function test_passes_uniqueness_probe_while_loop(): void
    {
        // Generate-until-unique idiom: the exists() query IS the loop condition and the
        // probed value ($code) is reassigned each iteration. This is a bounded uniqueness
        // search, not a per-row N+1, and the eager-loading remediation does not apply.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Question;
use Illuminate\Support\Str;

class CatalogueService
{
    private function generateCode($pillar, string $text): string
    {
        $base = $pillar->slug.'_'.Str::slug($text, '_');
        $code = $base;
        $n = 1;
        while (Question::where('code', $code)->exists()) {
            $code = $base.'_'.(++$n);
        }

        return $code;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CatalogueService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_uniqueness_probe_do_while_loop(): void
    {
        // Same idiom in do-while form: probed value reassigned in the body, exists() in the
        // condition.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Post;
use Illuminate\Support\Str;

class SlugGenerator
{
    public function unique(string $base): string
    {
        $slug = $base;
        do {
            $slug = $base.'-'.Str::random(4);
        } while (Post::where('slug', $slug)->exists());

        return $slug;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/SlugGenerator.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_detects_exists_check_per_item_in_foreach(): void
    {
        // A genuine N+1: running an existence check for every item in a fetched collection.
        // This is NOT a uniqueness-probe condition, so it must remain flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Question;

class Importer
{
    public function run(array $codes): array
    {
        $existing = [];
        foreach ($codes as $code) {
            if (Question::where('code', $code)->exists()) {
                $existing[] = $code;
            }
        }

        return $existing;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Importer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
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

        $this->assertWarning($result);
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

    public function test_passes_with_inline_foreach_closure_eager_loading(): void
    {
        // Mirrors Compass AssessmentService::stageQuestionCodes: eager loading applied inline
        // in the foreach() expression via a closure-constrained relation.
        $code = <<<'PHP'
<?php

namespace App\Services\Assessment;

class AssessmentService
{
    public function stageQuestionCodes()
    {
        $codesByPillar = [];
        foreach (Pillar::with(['questions' => fn ($q) => $q->where('is_active', true)])->orderBy('display_order')->get() as $pillar) {
            $questions = $pillar->questions->map(fn ($question) => $question->code)->all();
            $codesByPillar[$pillar->slug] = $questions;
        }

        return $codesByPillar;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Assessment/AssessmentService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_assigned_closure_keyed_eager_loading(): void
    {
        // Mirrors Compass CatalogueController::index: closure-keyed eager loading with a
        // nested ->with() assigned to a variable, then iterated.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers\Staff;

class CatalogueController
{
    public function index()
    {
        $pillars = Pillar::with([
            'questions' => fn ($q) => $q->withoutGlobalScopes()->with('options')->orderBy('display_order'),
        ])->orderBy('display_order')->get();

        foreach ($pillars as $pillar) {
            echo $pillar->questions->count();
        }

        return $pillars;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/Staff/CatalogueController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_standalone_aggregate_not_in_loop(): void
    {
        // Mirrors Compass ConsoleMetricsService::kpis: standalone aggregate queries are
        // not per-row loops and must not be flagged as N+1.
        $code = <<<'PHP'
<?php

namespace App\Services\Console;

class ConsoleMetricsService
{
    public function kpis()
    {
        return [
            'completed' => Assessment::where('status', 'completed')->count(),
            'total' => Business::count(),
        ];
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Console/ConsoleMetricsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_column_constrained_eager_loading(): void
    {
        // with('project:id,uuid,name') — Laravel column-selection syntax.
        // The ':id,uuid,name' suffix is stripped at runtime; the relationship name is 'project'.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class DashboardStatsService
{
    public function recentReports()
    {
        $reports = Report::query()
            ->with('project:id,uuid,name')
            ->get();

        foreach ($reports as $report) {
            echo $report->project->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/DashboardStatsService.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_passes_with_single_relationship_string(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            echo $post->user->name;
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

    public function test_passes_with_static_call_with(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with(['user'])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
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

    public function test_detects_in_for_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        for ($i = 0; $i < count($posts); $i++) {
            // Not detected - for loops don't track loop variable
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

        // For loops without tracked variables should pass
        $this->assertPassed($result);
    }

    public function test_detects_in_nested_foreach_loops(): void
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
            echo $post->user->name; // N+1 on outer loop

            foreach ($post->comments as $comment) {
                echo $comment->author->name; // N+1 on inner loop
            }
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

        $this->assertWarning($result);
        // Should detect at least the outer loop N+1
        $this->assertHasIssueContaining('user', $result);
    }

    public function test_passes_for_common_model_properties(): void
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
            echo $post->id;
            echo $post->name;
            echo $post->email;
            echo $post->created_at;
            echo $post->updated_at;
            echo $post->deleted_at;
            echo $post->title;
            echo $post->content;
            echo $post->status;
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

    public function test_deduplicates_same_relationship_multiple_times(): void
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
            echo $post->user->name;  // Line 10
            echo $post->user->email; // Line 11 - same relationship
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

        $this->assertWarning($result);
        // Should only report 'user' once (deduplicated)
        $issues = $result->getIssues();
        $this->assertCount(1, $issues);
    }

    public function test_passes_with_load_method(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $posts->load('user');

        foreach ($posts as $post) {
            echo $post->user->name;
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

    public function test_passes_when_load_missing_used(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $posts->loadMissing('user');

        foreach ($posts as $post) {
            echo $post->user->name;
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

    public function test_handles_parse_errors_gracefully(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all(
        // Invalid syntax - missing closing parenthesis
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/PostController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should not crash, should pass (no valid files to analyze)
        $this->assertPassed($result);
    }

    public function test_detects_different_variables_same_relationship_same_line(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $comments = Comment::all();

        foreach ($posts as $post) {
            echo $post->user->name;
        }

        foreach ($comments as $comment) {
            echo $comment->user->name; // Same relationship, different variable
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

        $this->assertWarning($result);
        // Should detect both (fixed deduplication bug)
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_with_multiple_with_calls(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->with('comments')->get();

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

    public function test_detects_nested_relationship_n_plus_one(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            // user is eager loaded, but user->team is not
            echo $post->user->team->name;
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('user.team', $result);
    }

    public function test_passes_with_dot_notation_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team')->get();

        foreach ($posts as $post) {
            echo $post->user->team->name;
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

    public function test_detects_partial_eager_loading_missing_nested(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        // Only 'user' is eager loaded, not 'user.profile'
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            echo $post->user->profile->bio; // N+1 on profile
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

        $this->assertWarning($result);
        $this->assertHasIssueContaining('user.profile', $result);
    }

    public function test_handles_deep_nested_relationships(): void
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
            // Deep nesting: 4 levels
            echo $post->user->team->department->company->name;
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

        $this->assertWarning($result);
        // Should detect the deepest nested relationship that looks like a relationship
        $this->assertHasIssueContaining('user.team.department.company', $result);
    }

    public function test_passes_with_deep_dot_notation_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team.department')->get();

        foreach ($posts as $post) {
            echo $post->user->team->department->name;
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

    public function test_nested_chain_ending_with_property_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with('user')->get();

        foreach ($posts as $post) {
            // 'name' is a property, not a relationship
            echo $post->user->name;
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

        // Should pass because 'user' is eager loaded and 'name' is a property
        $this->assertPassed($result);
    }

    public function test_multiple_nested_relationships_detected(): void
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
            echo $post->user->team->name;       // N+1 on user.team
            echo $post->category->parent->name; // N+1 on category.parent
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

        $this->assertWarning($result);
        $issues = $result->getIssues();
        // Should detect multiple nested relationship issues
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_with_relation_loaded_check_in_if_condition(): void
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
            if ($post->relationLoaded('user')) {
                echo $post->user->name;
            }
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

        // Should pass - developer checked with relationLoaded()
        $this->assertPassed($result);
    }

    public function test_passes_with_relation_loaded_in_ternary(): void
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
            $userName = $post->relationLoaded('user') ? $post->user->name : 'Unknown';
            echo $userName;
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

        // Should pass - developer checked with relationLoaded()
        $this->assertPassed($result);
    }

    public function test_passes_with_relation_loaded_early_return(): void
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
            if (!$post->relationLoaded('user')) {
                continue;
            }
            echo $post->user->name;
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

        // Should pass - developer checked with relationLoaded() before access
        $this->assertPassed($result);
    }

    public function test_relation_loaded_does_not_protect_unrelated_relationships(): void
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
            if ($post->relationLoaded('user')) {
                echo $post->user->name;
            }
            // Comments is NOT checked with relationLoaded()
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

        // Should fail - comments relationship is not protected
        $this->assertWarning($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_relation_loaded_protects_nested_relationships(): void
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
            if ($post->relationLoaded('user')) {
                // Accessing nested relationships is also protected
                echo $post->user->team->name;
            }
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

        // Should pass - the first relationship in chain (user) was checked
        $this->assertPassed($result);
    }

    public function test_relation_loaded_check_does_not_leak_between_loops(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::all();
        $comments = Comment::all();

        foreach ($posts as $post) {
            if ($post->relationLoaded('author')) {
                echo $post->author->name;
            }
        }

        // New loop - relationLoaded check from previous loop should not apply
        foreach ($comments as $comment) {
            echo $comment->author->name;
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

        // Should fail - the second loop's author access is not protected
        $this->assertWarning($result);
        $this->assertHasIssueContaining('author', $result);
    }

    public function test_detects_query_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_detects_find_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $userIds = [1, 2, 3, 4, 5];

        foreach ($userIds as $userId) {
            $user = User::find($userId);
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
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_does_not_flag_update_or_create_inside_loop(): void
    {
        // updateOrCreate() is a deliberate per-row write, not an accidental read N+1.
        $code = <<<'PHP'
<?php

namespace App\Services;

class CatalogueImporter
{
    public function import(array $pillars)
    {
        foreach ($pillars as $data) {
            Pillar::updateOrCreate(['slug' => $data['slug']], $data);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/CatalogueImporter.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_first_or_create_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class TagSyncer
{
    public function sync(array $tags)
    {
        foreach ($tags as $name) {
            Tag::firstOrCreate(['name' => $name]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/TagSyncer.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_upsert_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Services;

class PriceWriter
{
    public function write(array $batches)
    {
        foreach ($batches as $batch) {
            Price::upsert($batch, ['sku'], ['amount']);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/PriceWriter.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_skips_seeder_files_for_query_in_loop(): void
    {
        // A read-per-iteration that WOULD flag under app/ — proves the directory skip
        // works independently of the write-upsert exclusion.
        $code = <<<'PHP'
<?php

namespace Database\Seeders;

class CatalogueSeeder
{
    public function run()
    {
        $rows = [['code' => 'a'], ['code' => 'b']];

        foreach ($rows as $row) {
            $lookup = Lookup::where('code', $row['code'])->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'database/seeders/CatalogueSeeder.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['database']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_first_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class OrderController
{
    public function index()
    {
        $items = Item::all();

        foreach ($items as $item) {
            $product = Product::where('sku', $item->sku)->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/OrderController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Product::where', $result);
    }

    public function test_detects_multiple_queries_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ReportController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
            $payments = Payment::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ReportController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $issues = $result->getIssues();
        $this->assertGreaterThanOrEqual(2, count($issues));
    }

    public function test_passes_when_query_is_outside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();
        $allOrders = Order::all(); // Query outside loop is fine

        foreach ($users as $user) {
            echo $user->name;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_count_aggregate_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StatsController
{
    public function index()
    {
        $categories = Category::all();

        foreach ($categories as $category) {
            $productCount = Product::where('category_id', $category->id)->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StatsController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Product::where', $result);
    }

    public function test_passes_with_closure_keyed_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with([
            'user' => fn ($q) => $q->select('id', 'name'),
            'comments.author',
        ])->get();

        foreach ($posts as $post) {
            echo $post->user->name;
            echo $post->comments->first()->author->name;
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

    public function test_passes_with_mixed_closure_and_string_eager_loading(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function index()
    {
        $posts = Post::with([
            'user' => function ($query) {
                $query->select('id', 'name', 'email');
            },
            'tags',
            'category' => fn ($q) => $q->withCount('products'),
        ])->get();

        foreach ($posts as $post) {
            echo $post->user->email;
            echo $post->tags->pluck('name');
            echo $post->category->name;
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

    public function test_does_not_flag_cache_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Cache;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Cache::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_config_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Config;

class UserController
{
    public function index()
    {
        $items = Item::all();

        foreach ($items as $item) {
            $setting = Config::get('app.timezone');
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Config::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_session_facade_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Session;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $data = Session::get('user_data_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - Session::get() is not a database query
        $this->assertPassed($result);
    }

    public function test_does_not_flag_query_not_dependent_on_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // This query doesn't use $user at all - same query repeated
            $admins = Admin::where('active', true)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable (wasteful but not N+1)
        $this->assertPassed($result);
    }

    public function test_does_not_flag_chunk_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            Order::where('user_id', $user->id)->chunk(100, function($orders) {
                // Process chunk
            });
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - chunk() is intentional batching
        $this->assertPassed($result);
    }

    public function test_does_not_flag_cursor_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            foreach (Order::where('user_id', $user->id)->cursor() as $order) {
                // Process order
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - cursor() is memory-efficient streaming
        $this->assertPassed($result);
    }

    public function test_does_not_flag_lazy_inside_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->lazy();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - lazy() is memory-efficient streaming
        $this->assertPassed($result);
    }

    public function test_flags_query_dependent_on_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where('user_id', $user->id)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - classic N+1, query depends on $user
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_flags_query_with_loop_variable_in_closure(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::where(fn($q) => $q->where('user_id', $user->id))->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - closure captures loop variable
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_flags_query_with_loop_variable_in_arrow_function(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $orders = Order::whereHas('items', fn($q) => $q->where('buyer_id', $user->id))->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - arrow function references loop variable
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::whereHas', $result);
    }

    public function test_does_not_flag_multiple_non_query_facades(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
            $setting = Config::get('users.default_role');
            $session = Session::get('user_pref_' . $user->id);
            $logged = Log::info('Processing user ' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - none of these are database queries
        $this->assertPassed($result);
    }

    public function test_flags_a_query_on_a_model_whose_short_name_matches_a_facade(): void
    {
        // Regression test for #423: `use App\Models\Event` leaves the reference written as a
        // bare `Event`, which the non-query list matched on its last segment against the Event
        // facade. The model was exempted from the very check this analyzer exists to run.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Event;

class Probe
{
    public function run(array $ids)
    {
        foreach ($ids as $id) {
            $rows = Event::where('user_id', $id)->get();
            echo count($rows);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Probe.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Event::where', $result);
    }

    public function test_flags_a_facade_named_model_called_from_its_own_namespace(): void
    {
        // The other half of #423: nothing imports `Event` here, so it resolves through the
        // current namespace rather than a use statement. Both spellings have to reach the
        // model, or a caller that happens to sit beside it keeps the facade's exemption.
        $code = <<<'PHP'
<?php

namespace App\Models;

class EventReport
{
    public function build(array $ids)
    {
        foreach ($ids as $id) {
            $rows = Event::where('user_id', $id)->get();
            echo count($rows);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/EventReport.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Event::where', $result);
    }

    public function test_does_not_flag_a_facade_written_with_a_leading_backslash(): void
    {
        // `\Cache::get()` is the container alias spelled out. It resolves to the root
        // namespace, which is the one place the short-name fallback still applies.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = \Cache::get('user_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_a_facade_in_a_file_with_no_namespace(): void
    {
        // Nothing to resolve against, so `Cache` stays unqualified and reaches the exemption
        // on its bare name, exactly as the alias loader would resolve it at runtime.
        $code = <<<'PHP'
<?php

class LegacyController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/LegacyController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_exempts_an_http_client_matched_on_its_bare_name_in_a_namespaced_file(): void
    {
        // Guzzle, Soap and Curl sit in the non-query list under a bare name because they have
        // no single canonical namespace. A bare entry is a deliberate short-name rule, so the
        // application's own wrapper has to keep the exemption wherever it happens to live.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Support\Curl;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $body = Curl::get('https://example.test/' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_flags_a_chained_query_on_a_model_whose_short_name_is_db(): void
    {
        // The DB skip sitting beside the facade list is the same short-name match #423 was
        // filed about: an application model called DB borrowed the facade's blanket exemption.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\DB;

class Probe
{
    public function run(array $ids)
    {
        foreach ($ids as $id) {
            $rows = DB::where('user_id', $id)->get();
            echo count($rows);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Probe.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('DB::where', $result);
    }

    public function test_does_not_flag_the_db_facade_itself(): void
    {
        // The counterpart: the real facade, however it is spelled, still has its own handling
        // and must not start reporting once the skip matches on the resolved name.
        $code = <<<'PHP'
<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class Probe
{
    public function run(array $ids)
    {
        foreach ($ids as $id) {
            $rows = DB::where('user_id', $id)->get();
            echo count($rows);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Probe.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_still_analyzes_a_file_whose_imports_php_would_reject(): void
    {
        // A duplicate alias is invalid PHP and resolving names on it throws. The file still
        // parsed, so dropping it would lose a real finding with nothing recorded anywhere to
        // say a file had been skipped. Only the resolution degrades: `Order` is matched as
        // written, which is what this analyzer did before it resolved names at all.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Order;
use App\Other\Order;

class Probe
{
    public function run(array $ids)
    {
        foreach ($ids as $id) {
            $rows = Order::where('user_id', $id)->get();
            echo count($rows);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Probe.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Order::where', $result);
    }

    public function test_resolves_the_names_that_do_not_collide_in_a_file_php_would_reject(): void
    {
        // Giving up on the whole file costs more than the alias that collided. Matching falls
        // back to every name as written, so `Event` takes the Event facade's exemption on its
        // last segment and the query it guards goes unreported. `Event` still resolves, and
        // the model it names is still not a facade.
        //
        // Only `Cache` is ambiguous here, and NameContext records the collision and keeps the
        // first spelling. That is observable rather than merely documented: the first `use`
        // names the facade, which is exempt, so the `Cache` query must not be reported. Were
        // the last spelling to win instead, `App\Models\Cache` is no facade and that same
        // query would be flagged.
        $code = <<<'PHP'
<?php

namespace App\Services;

use App\Models\Event;
use Illuminate\Support\Facades\Cache;
use App\Models\Cache;

class Probe
{
    public function run(array $ids)
    {
        foreach ($ids as $id) {
            $rows = Event::where('user_id', $id)->get();
            echo count($rows);
        }

        foreach ($ids as $id) {
            $hits = Cache::where('user_id', $id)->get();
            echo count($hits);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Services/Probe.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // The name that does not collide still resolves, and the model it names is no facade.
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Event::where', $result);

        // The name that does collide kept its first import, so it is still the exempt facade.
        foreach ($result->getIssues() as $issue) {
            $this->assertStringNotContainsString('Cache::where', $issue->message);
        }
    }

    public function test_flags_an_unimported_facade_spelling_in_a_namespaced_file(): void
    {
        // `Cache` with no import inside a namespace resolves to App\Http\Controllers\Cache,
        // and that is what PHP would look for too: class names do not fall back to the global
        // namespace, so this code cannot run as written. Treating it as the application's own
        // class is the same rule that keeps App\Models\Event out of the facade's exemption,
        // and the four fixtures above carry the import precisely because of it.
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            $cached = Cache::get('user_' . $user->id);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Cache::get', $result);
    }

    public function test_flags_direct_find_with_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $userIds = [1, 2, 3, 4, 5];

        foreach ($userIds as $userId) {
            $user = User::find($userId);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should FAIL - find() with loop variable is N+1
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_does_not_flag_find_without_loop_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $items = Item::all();
        $adminId = 1;

        foreach ($items as $item) {
            // Query doesn't depend on $item, uses constant $adminId
            $admin = User::find($adminId);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable
        $this->assertPassed($result);
    }

    public function test_does_not_flag_query_when_closure_captures_but_does_not_use_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // Closure captures $user but doesn't use it - query doesn't depend on $user
            // This is not a true N+1 pattern (same query every iteration, not loop-dependent)
            $posts = Post::where('active', true)->get(function($q) use ($user) {
                $q->where('published', true); // No $user reference
            });
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - query doesn't depend on loop variable (just captured, not used)
        // This fixes false positives where closure captures variable but doesn't use it
        $this->assertPassed($result);
    }

    public function test_flags_query_when_closure_uses_captured_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $users = User::all();

        foreach ($users as $user) {
            // Closure captures AND uses $user - query depends on $user, legitimate N+1
            $posts = Post::where(function($q) use ($user) {
                $q->where('user_id', $user->id); // Actually uses $user
            })->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should fail - this is a legitimate N+1 query
        $this->assertFailed($result);
    }

    public function test_for_loop_flags_query_using_counter_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $ids = [1, 2, 3, 4, 5];

        for ($i = 0; $i < count($ids); $i++) {
            // Query uses $i in array access - true N+1 pattern
            $user = User::find($ids[$i]);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $i (counter variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_for_loop_ignores_query_not_using_counter(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        for ($i = 0; $i < 10; $i++) {
            // Same query every iteration - doesn't use $i
            $admins = User::where('role', 'admin')->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $i
        $this->assertPassed($result);
    }

    public function test_while_loop_flags_query_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $page = 1;
        $hasMore = true;

        while ($hasMore && $page < 100) {
            // Query uses $page - true N+1 pattern
            $records = Record::where('page', $page)->get();
            $page++;
            $hasMore = count($records) > 0;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $page (condition variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::where', $result);
    }

    public function test_while_loop_ignores_query_not_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $hasMore = true;

        while ($hasMore) {
            // Same query every iteration - doesn't use $hasMore
            $config = Config::get('key');
            $hasMore = someExternalCheck();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - Config::get is not a query, and doesn't use $hasMore
        $this->assertPassed($result);
    }

    public function test_do_while_flags_query_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $cursor = 0;

        do {
            // Query uses $cursor - true N+1 pattern
            $records = Record::where('id', '>', $cursor)->first();
            $cursor = $records ? $records->id : null;
        } while ($cursor !== null);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - uses $cursor (condition variable) in query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::where', $result);
    }

    public function test_do_while_ignores_query_not_using_condition_variable(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $shouldContinue = true;

        do {
            // Same query every iteration - doesn't use $shouldContinue
            $settings = Setting::where('key', 'default')->first();
            $shouldContinue = someCheck();
        } while ($shouldContinue);
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $shouldContinue
        $this->assertPassed($result);
    }

    public function test_for_loop_with_no_init_does_not_flag(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $i = 0;
        // For loop with no init expression
        for (; $i < 10; $i++) {
            $admins = User::where('role', 'admin')->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - can't track loop variable when init is empty
        $this->assertPassed($result);
    }

    public function test_while_loop_with_method_call_condition_ignores_unrelated_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $iterator = new Iterator();

        while ($iterator->hasNext()) {
            // Query doesn't use iterator
            $users = User::where('active', true)->get();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should NOT flag - query doesn't depend on $iterator
        $this->assertPassed($result);
    }

    public function test_while_loop_with_method_call_condition_flags_related_query(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function index()
    {
        $iterator = new Iterator();

        while ($iterator->hasNext()) {
            // Query uses iterator
            $record = Record::find($iterator->current());
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - query uses $iterator
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Record::find', $result);
    }

    // -------------------------------------------------------------------------
    // Registry-based detection tests (EloquentModelRelationshipScanner)
    // -------------------------------------------------------------------------

    public function test_does_not_flag_hash_column_when_model_has_no_such_relationship(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Project;

class ValidateSatisAuth
{
    public function handle()
    {
        $projects = Project::get();

        foreach ($projects as $project) {
            echo $project->api_token_hash;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Project.php' => $modelCode,
            'app/Http/Controllers/ValidateSatisAuth.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_result_count_columns_when_model_has_no_such_relationship(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class ProjectController
{
    public function show()
    {
        $reports = Report::get();

        foreach ($reports as $report) {
            echo $report->passed;
            echo $report->failed;
            echo $report->warnings;
            echo $report->errors;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/ProjectController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relationship_from_scanned_model_file(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->comments;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_passes_when_scanned_relationship_is_eager_loaded(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::with('comments')->get();

        foreach ($posts as $post) {
            echo $post->comments;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_eager_load_prefix_covers_intermediate_access(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::with('user.team')->get();

        foreach ($posts as $post) {
            echo $post->user;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_infers_model_type_through_collection_variable(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function tags()
    {
        return $this->belongsToMany(Tag::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->tags;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('tags', $result);
    }

    public function test_does_not_flag_find_result_scalar_columns(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function show($id)
    {
        $post = Post::find($id);

        foreach ([$post] as $p) {
            echo $p->title;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_detects_relation_method_query_call_in_loop(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            $count = $post->comments()->count();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('comments', $result);
    }

    public function test_does_not_flag_property_access_when_variable_type_is_unknown(): void
    {
        // Simulates $projects = $user->teams()->flatMap(...) — no static-call type inference.
        // When the loop variable's model type cannot be determined, the analyzer should
        // stay silent rather than guess (conservative: false negatives over false positives).
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Project;

class ValidateSatisAuth
{
    public function handle($user)
    {
        // flatMap produces an unknown-type collection — no static-call signature
        $projects = $user->teams()->with('projects')->get()->flatMap(
            fn ($team) => $team->projects
        );

        foreach ($projects as $project) {
            echo $project->api_token_hash;
            echo $project->passed;
            echo $project->total_issues;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Project.php' => $modelCode,
            'app/Http/Controllers/ValidateSatisAuth.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_when_model_is_in_registry_but_property_is_not_a_relationship(): void
    {
        // When we have precise type info AND the model is in the registry,
        // any property NOT listed as a relationship must not be flagged.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    protected $fillable = ['passed', 'failed', 'warnings', 'errors', 'skipped'];

    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Report;

class DashboardController
{
    public function index()
    {
        $reports = Report::get();

        foreach ($reports as $report) {
            echo $report->passed;
            echo $report->failed;
            echo $report->warnings;
            echo $report->errors;
            echo $report->skipped;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Report.php' => $modelCode,
            'app/Http/Controllers/DashboardController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_accessor_property_when_model_is_in_registry(): void
    {
        // Accessor methods (getXxxAttribute) should not be flagged as relationships.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    public function getFullTitleAttribute()
    {
        return $this->title . ' — ' . $this->subtitle;
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::get();

        foreach ($posts as $post) {
            echo $post->full_title;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => $modelCode,
            'app/Http/Controllers/PostController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_does_not_flag_accessor_property_when_model_has_no_relationships(): void
    {
        // Regression test: Config defines zero relationships, so it never enters the
        // relationshipRegistry (which is keyed only by models that define at least one
        // relationship). That used to make relationshipEvidence() fall through
        // to the heuristic path, which has no accessor/attribute awareness and flagged
        // 'value_preview' as a probable relationship. Accessors must be suppressed
        // regardless of whether their model defines any relationships.
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Config extends Model
{
    public function getValuePreviewAttribute(): string
    {
        return str($this->value)->limit(50)->toString();
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Config;

class ConfigController
{
    public function index()
    {
        $configs = Config::all();

        foreach ($configs as $config) {
            echo $config->value_preview;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Config.php' => $modelCode,
            'app/Http/Controllers/ConfigController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    public function test_lock_for_update_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function issue(array $items): void
    {
        foreach ($items as $item) {
            // Pessimistic lock is inherently per-row - not an N+1 to fix
            $stock = StoreItem::lockForUpdate()->whereKey($item['id'])->firstOrFail();
            $stock->decrement('quantity', $item['qty']);
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - a lockForUpdate chain cannot be eager-loaded or batched
        $this->assertPassed($result);
    }

    public function test_shared_lock_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function read(array $ids): void
    {
        foreach ($ids as $id) {
            $row = StoreItem::where('id', $id)->sharedLock()->first();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - sharedLock anywhere in the chain marks it per-row
        $this->assertPassed($result);
    }

    public function test_lockless_chain_in_loop_is_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class StockController
{
    public function issue(array $items): void
    {
        foreach ($items as $item) {
            // Same shape as the lock tests but without a lock - genuine N+1
            $stock = StoreItem::whereKey($item['id'])->firstOrFail();
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/StockController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - loop-dependent query with no lock in the chain
        $this->assertFailed($result);
        $this->assertHasIssueContaining('StoreItem::whereKey', $result);
    }

    public function test_find_followed_by_return_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $incoming): string
    {
        foreach ($incoming as $employeeId) {
            if ($this->deployedElsewhere($employeeId)) {
                // Runs at most once: the branch unconditionally leaves the loop
                $employee = Employee::find($employeeId);

                return 'already deployed';
            }
        }

        return 'attached';
    }

    private function deployedElsewhere(int $id): bool
    {
        return $id > 100;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - the query's branch returns, so it executes at most once
        $this->assertPassed($result);
    }

    public function test_chain_query_followed_by_return_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $employee = Employee::where('id', $id)->first();

                return $employee;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - method-chain query followed by an unconditional return
        $this->assertPassed($result);
    }

    public function test_query_followed_by_throw_in_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function validateAll(array $ids): void
    {
        foreach ($ids as $id) {
            if ($id < 0) {
                $item = Item::find($id);

                throw new \RuntimeException('invalid item');
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - throw unconditionally exits the loop
        $this->assertPassed($result);
    }

    public function test_query_followed_by_break_in_single_loop_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstMatch(array $ids): void
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $match = Item::find($id);
                break;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - break exits the only enclosing loop
        $this->assertPassed($result);
    }

    public function test_query_followed_by_log_then_return_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AssignmentController
{
    public function attach(array $ids): string
    {
        foreach ($ids as $id) {
            if ($id > 100) {
                $employee = Employee::find($id);
                Log::info('conflict found');

                return 'conflict';
            }
        }

        return 'attached';
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AssignmentController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - plain expression statements cannot re-enter the loop
        $this->assertPassed($result);
    }

    public function test_query_in_if_with_return_after_if_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstOnly(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id > 0) {
                $item = Item::find($id);
            }

            return $item ?? null;
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - the loop body unconditionally returns after the if block
        $this->assertPassed($result);
    }

    public function test_query_in_elseif_and_else_followed_by_return_is_not_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function resolve(array $ids): ?object
    {
        foreach ($ids as $id) {
            if ($id === 0) {
                continue;
            } elseif ($id < 100) {
                $a = Item::find($id);

                return $a;
            } else {
                $b = Item::find($id);

                return $b;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should pass - both branches unconditionally return after their query
        $this->assertPassed($result);
    }

    public function test_query_with_conditional_return_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class UserController
{
    public function firstActive(array $ids): ?object
    {
        foreach ($ids as $id) {
            // The query runs every iteration; only the return is conditional
            $user = User::find($id);
            if ($user !== null) {
                return $user;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/UserController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - the loop can iterate again after the query
        $this->assertFailed($result);
        $this->assertHasIssueContaining('User::find', $result);
    }

    public function test_query_followed_by_break_in_nested_loop_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function scan(array $groups): void
    {
        foreach ($groups as $group) {
            foreach ($group as $id) {
                if ($id > 5) {
                    // break only exits the inner loop; the outer loop repeats
                    $item = Item::find($id);
                    break;
                }
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - the query can run once per outer iteration
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Item::find', $result);
    }

    public function test_query_then_return_inside_try_still_flagged(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController
{
    public function firstResolvable(array $ids): ?object
    {
        foreach ($ids as $id) {
            try {
                $item = Item::find($id);

                return $item;
            } catch (\Throwable $e) {
                // A throwing query is caught and the loop resumes
                continue;
            }
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/ItemController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - inside try, the loop can resume via the catch block
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Item::find', $result);
    }

    public function test_query_in_while_condition_still_flagged_despite_return_after_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class CategoryController
{
    public function rootOf(array $seeds): mixed
    {
        foreach ($seeds as $seed) {
            $currentId = $seed;
            // The query re-runs on every while iteration - the return below
            // only exits after the whole chain walk
            while ($category = Category::find($currentId)) {
                $currentId = $category->parent_id;
            }

            return $currentId;
        }

        return null;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/CategoryController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        // Should flag - a loop-header query repeats even though the outer
        // foreach body ends in a return
        $this->assertFailed($result);
        $this->assertHasIssueContaining('Category::find', $result);
    }

    // -------------------------------------------------------------------------
    // Column-vs-relationship naming on models outside the scanned paths
    // -------------------------------------------------------------------------

    /**
     * A model that lives in a package is never scanned, so it never enters the
     * relationship registry and the property name falls through to the naming heuristic.
     * Every name here is a plain column on a row that is already in memory: the two halves
     * of a morphTo pair, plus ordinary snake_case columns. Reading them costs no query.
     */
    public function test_does_not_flag_snake_case_columns_on_unscanned_model(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Vendor\Audit\Models\AuditEntry;

class AuditController
{
    public function index()
    {
        $entries = AuditEntry::get();

        foreach ($entries as $entry) {
            echo $entry->subject_type;
            echo $entry->causer_type;
            echo $entry->log_name;
            echo $entry->batch_uuid;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuditController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Recall guard for the change above. A relationship accessor is a method name, so it is
     * camelCase or a single lowercase word, never snake_case. Narrowing the heuristic to
     * treat snake_case as a column must not silence the singular morphTo/belongsTo access
     * that is the classic N+1 shape on an unscanned model.
     */
    public function test_still_flags_singular_relationship_on_unscanned_model(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Vendor\Audit\Models\AuditEntry;

class AuditController
{
    public function index()
    {
        $entries = AuditEntry::get();

        foreach ($entries as $entry) {
            echo $entry->causer;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuditController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('causer', $result);
    }

    /**
     * Boundary between the two conventions. Columns are snake_case, relationship methods are
     * camelCase, so a camelCase name keeps its relationship reading even when it ends in the
     * same word as a polymorphic type column.
     */
    public function test_camel_case_type_suffix_is_still_treated_as_relationship(): void
    {
        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Vendor\Audit\Models\AuditEntry;

class AuditController
{
    public function index()
    {
        $entries = AuditEntry::get();

        foreach ($entries as $entry) {
            echo $entry->subjectType;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Http/Controllers/AuditController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('subjectType', $result);
    }

    /**
     * The naming heuristic only ever runs for models outside the scanned paths. A scanned
     * model is answered by exact registry lookup, so a legacy snake_case relationship method
     * keeps being detected: narrowing the heuristic costs nothing once the model file is
     * visible to the analyzer.
     */
    public function test_snake_case_relationship_on_scanned_model_is_still_flagged(): void
    {
        $modelCode = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Legacy extends Model
{
    public function user_profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP;

        $controllerCode = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Legacy;

class LegacyController
{
    public function index()
    {
        $records = Legacy::get();

        foreach ($records as $legacy) {
            echo $legacy->user_profile;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            'app/Models/Legacy.php' => $modelCode,
            'app/Http/Controllers/LegacyController.php' => $controllerCode,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('user_profile', $result);
    }
    // -------------------------------------------------------------------------
    // Relationships reached through traits and parent classes
    // -------------------------------------------------------------------------

    /**
     * A model states only part of itself in its own body. Here the relationship lives in a
     * trait, and the model separately declares one of its own, which is what used to hide
     * the problem: declaring any relationship put the model in the registry, and the
     * registry was then answered by exact lookup with no fallback, so the trait's
     * relationship was reported as "not a relationship" rather than as a lazy load.
     */
    public function test_flags_relationship_declared_in_a_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile;
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use HasProfile;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->profile;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('profile', $result);
    }

    /**
     * The same blind spot on the inheritance axis: a child model inherits its parent's
     * relationships, and reading one of them in a loop is the same lazy load it would be
     * had the child declared it.
     */
    public function test_flags_relationship_inherited_from_a_scanned_parent(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseUser.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseUser extends Model
{
    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
PHP,
            'app/Models/Admin.php' => <<<'PHP'
<?php

namespace App\Models;

class Admin extends BaseUser
{
    public function logs()
    {
        return $this->hasMany(Log::class);
    }
}
PHP,
            'app/Http/Controllers/AdminController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Admin;

class AdminController
{
    public function index()
    {
        $admins = Admin::get();

        foreach ($admins as $admin) {
            echo $admin->posts;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('posts', $result);
    }

    /**
     * Traits compose traits, so resolution has to recurse rather than expand one level.
     * Illuminate\Notifications\Notifiable is exactly this shape.
     */
    public function test_flags_relationship_from_a_trait_used_by_another_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasAvatar.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Avatar;

trait HasAvatar
{
    public function avatar()
    {
        return $this->hasOne(Avatar::class);
    }
}
PHP,
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

trait HasProfile
{
    use HasAvatar;
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile;
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use HasProfile;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->avatar;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('avatar', $result);
    }

    /**
     * notifications() is a real morphMany that Notifiable contributes through
     * HasDatabaseNotifications, so reading it per row is a real N+1. The trait ships with
     * the framework and is never scanned, which is why the relationships it declares are
     * carried as data rather than discovered.
     */
    public function test_flags_notifications_reached_through_the_notifiable_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Account.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class Account extends Authenticatable
{
    use Notifiable;

    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
PHP,
            'app/Http/Controllers/AccountController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Account;

class AccountController
{
    public function index()
    {
        $accounts = Account::get();

        foreach ($accounts as $account) {
            echo $account->notifications;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('notifications', $result);
    }

    /**
     * A model may hand the body of a relationship off to a helper, which leaves the shape
     * matching nothing to recognise. The declared return type still names the contract.
     */
    public function test_flags_relationship_declared_only_by_its_return_type(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Widget.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Widget extends Model
{
    public function parts(): HasMany
    {
        return $this->buildParts();
    }

    private function buildParts()
    {
        return $this->hasMany(Part::class);
    }
}
PHP,
            'app/Http/Controllers/WidgetController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Widget;

class WidgetController
{
    public function index()
    {
        $widgets = Widget::get();

        foreach ($widgets as $widget) {
            echo $widget->parts;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('parts', $result);
    }

    /**
     * Relationship bodies are not always a single top-level return. A guard clause that
     * returns the relation from inside a conditional declares one just as plainly.
     */
    public function test_flags_relationship_returned_only_from_inside_a_conditional(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Ticket.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Ticket extends Model
{
    public function assignee()
    {
        if ($this->open) {
            return $this->belongsTo(User::class);
        }
    }

    public function reporter()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/TicketController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Ticket;

class TicketController
{
    public function index()
    {
        $tickets = Ticket::get();

        foreach ($tickets as $ticket) {
            echo $ticket->assignee;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('assignee', $result);
    }

    /**
     * Resolution is keyed on the declaration the scan saw, not on a file whose name
     * matches the class, so a trait sharing a file with the model that uses it resolves
     * like any other.
     */
    public function test_flags_relationship_from_a_trait_declared_in_the_same_file(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}

class Item extends Model
{
    use HasProfile;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->profile;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('profile', $result);
    }

    /**
     * Trait names are resolved through the importing file's use map, so an alias names the
     * same declaration the unaliased import would.
     */
    public function test_resolves_a_trait_imported_under_an_alias(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile as Profileable;
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use Profileable;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->profile;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('profile', $result);
    }

    /**
     * A group use carries its prefix separately from each imported name, and reports an
     * unknown import type when its items carry their own.
     */
    public function test_resolves_a_trait_imported_through_a_group_use(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\{HasProfile};
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use HasProfile;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->profile;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('profile', $result);
    }

    /**
     * PHP rejects a cyclic extends chain, but half-edited source still reaches the
     * scanner, and walking the graph must terminate rather than recurse until the stack
     * runs out. The reading then falls back to the naming heuristic, as it does for any
     * model the scanner could not read fully.
     */
    public function test_cyclic_extends_chain_terminates(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Alpha.php' => <<<'PHP'
<?php

namespace App\Models;

class Alpha extends Beta {}
PHP,
            'app/Models/Beta.php' => <<<'PHP'
<?php

namespace App\Models;

class Beta extends Alpha {}
PHP,
            'app/Http/Controllers/AlphaController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Alpha;

class AlphaController
{
    public function index()
    {
        $rows = Alpha::get();

        foreach ($rows as $row) {
            echo $row->widgets;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('widgets', $result);
    }

    /**
     * A closure's $this is the model, so a relation builder called inside one would be
     * attributed to whatever method happens to enclose the closure. Searching a body for
     * returns has to stop at the closure boundary.
     */
    public function test_relationship_returned_from_a_closure_is_not_registered(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Gadget.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Gadget extends Model
{
    public function register()
    {
        $callback = function () {
            return $this->hasMany(Part::class);
        };

        $callback();
    }

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/GadgetController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Gadget;

class GadgetController
{
    public function index()
    {
        $gadgets = Gadget::get();

        foreach ($gadgets as $gadget) {
            echo $gadget->register;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Only the tail of a property chain is judged against the loop variable's model, so
     * widening what counts as a relationship also widens the set of tails that match.
     * settings is a JSON column here, and eager loading the reported path would raise
     * RelationNotFoundException, which is what makes the finding worse than noise.
     */
    public function test_does_not_flag_a_nested_chain_whose_head_is_a_json_column(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Account.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class Account extends Authenticatable
{
    use Notifiable;

    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
PHP,
            'app/Http/Controllers/AccountController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Account;

class AccountController
{
    public function index()
    {
        $accounts = Account::get();

        foreach ($accounts as $account) {
            echo $account->settings->notifications;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Recall guard in the other direction: a trait's relationship is a relationship, so
     * eager loading it has to silence the finding exactly as it does for one the model
     * declares itself.
     */
    public function test_passes_when_a_trait_relationship_is_eager_loaded(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile;
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use HasProfile;

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::with('profile')->get();

        foreach ($items as $item) {
            echo $item->profile;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * $fillable, $casts and $appends are inherited like anything else, and the analyzer
     * already treats a declared attribute as proof that a name is a column rather than a
     * relationship. Reading the parent's declaration is what lets that proof apply.
     */
    public function test_does_not_flag_a_column_declared_fillable_on_a_parent_model(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    protected $fillable = ['sku'];

    public function owner()
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends BaseProduct {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * The same for accessors. An accessor exposes a computed property, never a
     * relationship, and putting one in a trait is the usual way to share it.
     */
    public function test_does_not_flag_an_accessor_declared_in_a_trait(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasSku.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

trait HasSku
{
    public function getSkuAttribute(): string
    {
        return strtoupper($this->code);
    }
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasSku;
use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    use HasSku;
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Knowing a name IS a relationship is not the same as knowing which names are not: the
     * chain may leave the scanned paths. So an inherited relationship must not, on its own,
     * start answering absent names conclusively. Item states none of its own and uses a
     * trait that ships in a package, so it cannot be read in full and sku stays a guess.
     */
    public function test_column_on_a_model_with_only_inherited_relations_is_still_heuristic(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile;
use Illuminate\Database\Eloquent\Model;
use Vendor\Pkg\HasThings;

class Item extends Model
{
    use HasProfile, HasThings;
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $items = Item::get();

        foreach ($items as $item) {
            echo $item->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    // -------------------------------------------------------------------------
    // Conclusive readings for models the scanner could read in full
    // -------------------------------------------------------------------------

    /**
     * The case the naming heuristic could never get right on its own. Product has no
     * relationships and extends a base that declares none, so every class it reaches was
     * read, and Eloquent resolves $product->sku through method_exists: no method named sku
     * exists anywhere in the chain, so sku is a column. Before, an absent name on a model
     * with no relationships at all fell through to the heuristic, which had only the shape
     * of the word to go on and answered yes.
     */
    public function test_does_not_flag_a_single_word_column_on_a_model_with_no_relationships(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * Nearly every generated model uses at least one framework trait, so a reading that
     * broke on them would apply to almost nothing. HasFactory and SoftDeletes declare no
     * relationships, which is carried as data because those declarations are never scanned.
     */
    public function test_does_not_flag_a_single_word_column_on_a_model_using_only_relation_free_framework_traits(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Product extends Model
{
    use HasFactory, SoftDeletes;
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * The counterpart to the notifications test: same shape of model, opposite polarity.
     * notifications is flagged because Notifiable really does declare it, and sku is not
     * because the chain was read to the end and nothing in it declares that method.
     */
    public function test_does_not_flag_a_single_word_column_on_a_user_model_extending_authenticatable(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Account.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class Account extends Authenticatable
{
    use Notifiable;
}
PHP,
            'app/Http/Controllers/AccountController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Account;

class AccountController
{
    public function index()
    {
        $rows = Account::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * A name carrying its own namespace needs no import, and resolution has to pass it
     * through rather than prepend the enclosing namespace to it.
     */
    public function test_does_not_flag_a_fully_qualified_eloquent_parent_without_a_use_statement(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Illuminate\Database\Eloquent\Model {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * The guard that keeps the conclusive reading honest. A trait that ships in a package
     * is never scanned, so its members are unknown and the model cannot be spoken for. It
     * keeps guessing, exactly as it did before.
     */
    public function test_still_flags_when_a_trait_is_outside_the_scan(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Vendor\Pkg\HasThings;

class Product extends Model
{
    use HasThings;
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * The same guard on the inheritance axis. A base class from a package may declare
     * relationships the scan never saw.
     */
    public function test_still_flags_when_the_parent_is_outside_the_scan(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Vendor\Pkg\BaseThing {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * Proving a name is not a relationship is not the same as failing to recognise one.
     * This relationship is returned from a match arm, which the shape matching does not
     * follow, but owner is still a method on the model, so the reading stays a guess and
     * the finding survives. That distinction is what keeps the conclusive answer from
     * depending on recognising every way a relationship can be written.
     */
    public function test_still_flags_a_method_that_exists_but_was_not_classified(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    public function owner()
    {
        return match ($this->kind) {
            default => $this->belongsTo(User::class),
        };
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->owner;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('owner', $result);
    }

    /**
     * An alias gives the class a relationship under a name that appears in neither the
     * trait nor the class body, so the flattened lists no longer describe the model.
     */
    public function test_trait_alias_adaptation_leaves_the_model_unread(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasProfile.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Profile;

trait HasProfile
{
    public function profile()
    {
        return $this->hasOne(Profile::class);
    }
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasProfile;
use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    use HasProfile {
        profile as author;
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * __get answers for names no declaration lists, so the member index stops being a
     * complete account of the model.
     */
    public function test_model_declaring_magic_get_is_left_unread(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    public function __get($key)
    {
        return $this->resolveDynamically($key);
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * The one way a relationship exists with no method of its name: a package registers
     * it on someone else's model from a service provider, and Eloquent answers it through
     * __call. Proving sku is absent would prove nothing about vendor, so the registration
     * is read and folded into the model it names.
     */
    public function test_relation_registered_by_resolve_relation_using_is_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Providers/RelationServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

use App\Models\Product;
use App\Models\Vendor;

class RelationServiceProvider
{
    public function boot()
    {
        Product::resolveRelationUsing('vendor', function ($product) {
            return $product->belongsTo(Vendor::class);
        });
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->vendor;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('vendor', $result);
    }

    /**
     * `parent::` forwards late static binding the way `self::` does, so a model that
     * registers through it extends itself, not its parent. Taken as a class name, `parent`
     * matched no declaration and the registration was dropped while the model still read
     * as fully known.
     */
    public function test_relation_registered_through_parent_is_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Item extends Model {}
PHP,
            'app/Models/Gadget.php' => <<<'PHP'
<?php

namespace App\Models;

class Gadget extends Item
{
    protected static function booted()
    {
        parent::resolveRelationUsing('maker', fn ($gadget) => $gadget->belongsTo(Maker::class));
    }
}
PHP,
            'app/Http/Controllers/GadgetController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Gadget;

class GadgetController
{
    public function index()
    {
        $gadgets = Gadget::get();

        foreach ($gadgets as $gadget) {
            echo $gadget->maker;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('maker', $result);
    }

    /**
     * When the registration names its model through a variable, any model could be the
     * one being extended, so no model can be spoken for and every reading falls back to
     * the heuristic.
     */
    public function test_unattributable_resolve_relation_using_withdraws_conclusive_readings(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Providers/RelationServiceProvider.php' => <<<'PHP'
<?php

namespace App\Providers;

class RelationServiceProvider
{
    public function boot()
    {
        foreach (config('extend.models') as $model) {
            $model::resolveRelationUsing('vendor', fn ($row) => $row->belongsTo($model));
        }
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * The lookup side only ever knows a model by its short name, so two classes sharing
     * one are answered together. Judging an absent name would then rest partly on a class
     * the code never referred to, so neither is spoken for.
     */
    public function test_shared_short_name_is_never_answered_conclusively(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Legacy/Product.php' => <<<'PHP'
<?php

namespace App\Legacy;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * Eloquent resolves $item->throughParts() by finding parts and hopping through it, so
     * no method of that name is declared and proving its absence proves nothing.
     */
    public function test_through_relation_method_is_not_answered_conclusively(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasParts.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\Part;

trait HasParts
{
    public function parts()
    {
        return $this->hasMany(Part::class);
    }
}
PHP,
            'app/Models/Item.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasParts;
use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    use HasParts;
}
PHP,
            'app/Http/Controllers/ItemController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Item;

class ItemController
{
    public function index()
    {
        $rows = Item::get();

        foreach ($rows as $row) {
            echo $row->throughParts()->count();
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('throughParts', $result);
    }

    /**
     * Isolates accessor flattening. On a model read in full the absent-method reading
     * would answer this anyway, so the fixture uses a package trait to withhold that and
     * leave the accessor as the only thing standing between the code and a finding.
     */
    public function test_inherited_accessor_suppresses_a_column_on_a_model_not_read_in_full(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasSku.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

trait HasSku
{
    public function getSkuAttribute(): string
    {
        return strtoupper($this->code);
    }
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasSku;
use Illuminate\Database\Eloquent\Model;
use Vendor\Pkg\HasThings;

class Product extends Model
{
    use HasSku, HasThings;
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * The same isolation for $fillable, $casts and $appends flattening.
     */
    public function test_inherited_fillable_suppresses_a_column_on_a_model_not_read_in_full(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Vendor\Pkg\HasThings;

class BaseProduct extends Model
{
    use HasThings;

    protected $fillable = ['sku'];
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends BaseProduct {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertPassed($result);
    }

    /**
     * A parent named without a namespace to resolve it against still names a class, and
     * that class may declare relationships the scan never saw. Reading such a name as
     * though the model had no parent at all would turn a model nothing is known about into
     * one with nothing left to read, which is the worst direction for this analyzer.
     */
    public function test_still_flags_when_an_unqualified_parent_cannot_be_found(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Thing.php' => <<<'PHP'
<?php

class Thing extends SomePackageBase {}
PHP,
            'app/Http/Controllers/ThingController.php' => <<<'PHP'
<?php

class ThingController
{
    public function index()
    {
        $rows = Thing::get();

        foreach ($rows as $row) {
            echo $row->owner;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('owner', $result);
    }

    /**
     * PHP resolves an unqualified name in the global namespace to the global one, so a
     * trait declared there is found like any other and the model it is used by can still
     * be read in full.
     */
    public function test_resolves_a_trait_in_the_global_namespace(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/HasParts.php' => <<<'PHP'
<?php

trait HasParts
{
    public function parts()
    {
        return $this->hasMany(Part::class);
    }
}
PHP,
            'app/Models/Thing.php' => <<<'PHP'
<?php

class Thing extends Illuminate\Database\Eloquent\Model
{
    use HasParts;
}
PHP,
            'app/Http/Controllers/ThingController.php' => <<<'PHP'
<?php

class ThingController
{
    public function index()
    {
        $rows = Thing::get();

        foreach ($rows as $row) {
            echo $row->parts;
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('parts', $result);
        $this->assertCount(1, $result->getIssues());
    }

    /**
     * PHP resolves a class name without regard to case, so `baseProduct` and `BaseProduct` name
     * one class. The scan used to key its declaration table on the name as written, so the
     * reference found nothing, the parent's $fillable was not inherited, and a plain column read
     * fell back to the name heuristic.
     */
    public function test_does_not_flag_a_column_declared_fillable_on_a_differently_cased_parent(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    protected $fillable = ['sku'];
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends baseProduct {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The same rule on the lookup side. `product::get()` names the class declared as `Product`,
     * but the registries were keyed by the short name as the declaration spells it and asked
     * with the name as the call site spells it, so the reference found no $fillable and a plain
     * column read fell back to the name heuristic.
     *
     * The parent is outside the scanned paths, so the model is not read in full and only the
     * $fillable lookup can answer sku. A model read in full would pass on its conclusive absence
     * alone, which the next test covers, and this one would then pin nothing of its own.
     */
    public function test_does_not_flag_a_fillable_column_on_a_model_referenced_in_a_different_case(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Acme\Catalog\RecordBase
{
    protected $fillable = ['sku'];
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The accessor lookup is keyed the same way, and on a model not read in full it is the only
     * thing that tells a computed property from a relationship.
     */
    public function test_does_not_flag_an_accessor_on_a_model_referenced_in_a_different_case(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Acme\Catalog\RecordBase
{
    public function getOwnerAttribute()
    {
        return $this->attributes['owner_name'];
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = product::get();

        foreach ($products as $product) {
            echo $product->owner;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The relationship lookup is keyed the same way, and missing it is a false negative. The
     * name heuristic takes category for a column, so only the registry knows Product declares
     * it as a relationship, and a reference in another case has to find that entry for the lazy
     * load in the loop to be reported.
     */
    public function test_flags_a_declared_relationship_on_a_model_referenced_in_a_different_case(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Acme\Catalog\RecordBase
{
    public function category()
    {
        return $this->belongsTo(Category::class);
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = product::get();

        foreach ($products as $product) {
            echo $product->category->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('category', $result);
    }

    /**
     * A model stating relationships of its own answers an absent name no, and that has to reach
     * a reference in another case too. The parent is outside the scanned paths, so the model is
     * not read in full and nothing else stops owner falling to the name heuristic.
     */
    public function test_answers_an_absent_name_from_own_relationships_for_a_model_referenced_in_a_different_case(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Acme\Catalog\RecordBase
{
    public function supplier()
    {
        return $this->belongsTo(Supplier::class);
    }
}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = product::get();

        foreach ($products as $product) {
            echo $product->owner;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A model read in full answers an absent name conclusively, and that reading has to reach a
     * reference spelled differently from the declaration too. Product declares no member named
     * sku anywhere in its chain, so sku cannot be a relationship however the call site writes
     * the class.
     */
    public function test_answers_an_absent_name_conclusively_for_a_model_referenced_in_a_different_case(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = PRODUCT::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Once the lookup ignores case, `Product` and `PRODUCT` are one name to it, so two classes
     * spelled that way share an entry exactly as two spelled alike do. Neither may be read
     * conclusively, or an absent name would be judged partly on a class the code never meant.
     */
    public function test_short_names_differing_only_in_case_are_never_answered_conclusively(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model {}
PHP,
            'app/Legacy/PRODUCT.php' => <<<'PHP'
<?php

namespace App\Legacy;

use Illuminate\Database\Eloquent\Model;

class PRODUCT extends Model {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $rows = Product::get();

        foreach ($rows as $row) {
            echo $row->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertHasIssueContaining('sku', $result);
    }

    /**
     * An import applies from its own line, not across the enclosing block, so the parent below
     * is App\Models\BaseProduct and not the one the trailing `use` names. Collecting a scope's
     * imports before walking it answered the other way.
     *
     * The two candidate parents have to disagree about `sku` for that to show: one declares it
     * fillable, the other declares a relationship of that name. A first attempt gave the wrong
     * parent nothing, and the test passed either way, because a parent that was found but wrong
     * still left the registry conclusive and `sku` still matched no relationship.
     */
    public function test_does_not_apply_an_import_written_after_the_class_it_would_reparent(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    protected $fillable = ['sku'];
}
PHP,
            'app/Other/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Other;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    public function sku()
    {
        return $this->belongsTo(\App\Models\Sku::class);
    }
}
PHP,
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends BaseProduct {}

use App\Other\BaseProduct;
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A name carrying a backslash is not necessarily fully qualified. In `namespace App`,
     * `extends Models\BaseProduct` names `App\Models\BaseProduct`, and resolveClassName()
     * returned any such name verbatim, so the declaration was never found and the parent's
     * $fillable was not inherited.
     */
    public function test_does_not_flag_a_column_declared_fillable_on_a_relative_qualified_parent(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    protected $fillable = ['sku'];
}
PHP,
            'app/Product.php' => <<<'PHP'
<?php

namespace App;

class Product extends Models\BaseProduct {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * The same rule reaches the first segment: `use App\Other\Models;` makes
     * `extends Models\BaseProduct` name `App\Other\Models\BaseProduct`, so the import has to
     * be consulted for a qualified name too, not only for a single-segment one.
     */
    public function test_resolves_a_relative_qualified_parent_through_an_imported_first_segment(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Other/Models/BaseProduct.php' => <<<'PHP'
<?php

namespace App\Other\Models;

use Illuminate\Database\Eloquent\Model;

class BaseProduct extends Model
{
    protected $fillable = ['sku'];
}
PHP,
            'app/Product.php' => <<<'PHP'
<?php

namespace App;

use App\Other\Models;

class Product extends Models\BaseProduct {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Laravel 11-13 declare a model's columns through class attributes and a casts() method as
     * well as through properties. A column declared either way is an attribute, so it is never
     * a relationship, including on a model not read in full, where the name heuristic would
     * otherwise answer it. Each project also holds a separate model whose author() relationship
     * is read in a loop, which has to keep firing.
     *
     * @dataProvider attributeDeclaredColumnProvider
     */
    #[DataProvider('attributeDeclaredColumnProvider')]
    public function test_does_not_flag_a_column_declared_by_an_attribute_or_casts_method(string $imports, string $attributes, string $body, string $column): void
    {
        $result = $this->analyzeAttributeDeclaredColumn($imports, $attributes, $body, $column);

        $this->assertSame([], $this->issueMessagesNaming($column, $result));
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'author'", $result);
    }

    /**
     * @return array<string, array{string, string, string, string}>
     */
    public static function attributeDeclaredColumnProvider(): array
    {
        return [
            'Fillable with an array' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable;',
                "#[Fillable(['subject', 'html'])]",
                '',
                'subject',
            ],
            'Fillable with variadic strings' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable;',
                "#[Fillable('subject', 'html')]",
                '',
                'subject',
            ],
            'Fillable imported under an alias' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable as F;',
                "#[F(['subject', 'html'])]",
                '',
                'subject',
            ],
            'Fillable written fully qualified' => [
                '',
                "#[\\Illuminate\\Database\\Eloquent\\Attributes\\Fillable(['subject', 'html'])]",
                '',
                'subject',
            ],
            'Appends' => [
                'use Illuminate\Database\Eloquent\Attributes\Appends;',
                "#[Appends(['teaser'])]",
                '',
                'teaser',
            ],
            'casts() returning an array literal' => [
                '',
                '',
                "protected function casts(): array\n    {\n        return ['headline' => 'string'];\n    }",
                'headline',
            ],
            'Attribute accessor read by its method name' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                "protected function shortTitle(): Attribute\n    {\n        return Attribute::make(get: fn (\$value) => strtoupper(\$value));\n    }",
                'shortTitle',
            ],
            'Attribute accessor imported under an alias' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute as Accessor;',
                '',
                "protected function headline(): Accessor\n    {\n        return Accessor::make(get: fn (\$value) => strtoupper(\$value));\n    }",
                'headline',
            ],
            'Attribute accessor with a nullable union return type' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function headline(): Attribute|null { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'headline',
            ],
            'Attribute accessor read in another case' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function SKU(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'sku',
            ],
            'Multi-word Attribute accessor read in lower case' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function fullHeadline(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'fullheadline',
            ],
            'get...Attribute accessor read in another case' => [
                '',
                '',
                'public function getSKUAttribute($value) { return strtoupper($value); }',
                'sku',
            ],
            'default in the attributes property' => [
                '',
                '',
                "protected \$attributes = ['headline' => 'draft'];",
                'headline',
            ],
            'casts() merging an array literal into the parent casts' => [
                '',
                '',
                "protected function casts(): array { return array_merge(parent::casts(), ['headline' => 'string']); }",
                'headline',
            ],
            'casts() adding the parent casts with +' => [
                '',
                '',
                "protected function casts(): array { return ['headline' => 'string'] + parent::casts(); }",
                'headline',
            ],
        ];
    }

    /**
     * A #[Fillable] attribute holding a constant the model declares lists that constant's
     * columns, so reading one in a loop is a column read, not a lazy load.
     */
    public function test_does_not_flag_a_column_a_fillable_attribute_lists_through_an_own_constant(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Bulletin.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Vendor\Pkg\HasThings;

#[Fillable(self::COLS)]
class Bulletin extends Model
{
    use HasThings;

    public const COLS = ['subject', 'body'];
}
PHP,
            'app/Http/Controllers/BulletinController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Bulletin;

class BulletinController
{
    public function index()
    {
        $bulletins = Bulletin::get();

        foreach ($bulletins as $b) {
            echo $b->subject;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * A casts() method that returns anything but an array literal names no column the scan can
     * read, so the column stays unknown and the name heuristic still answers it.
     */
    public function test_a_casts_method_returning_a_variable_leaves_the_column_unknown(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            '',
            '',
            "protected function casts(): array\n    {\n        \$casts = ['headline' => 'string'];\n\n        return \$casts;\n    }",
            'headline',
        );

        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining("'headline'", $result);
        $this->assertHasIssueContaining("'author'", $result);
    }

    /**
     * Only Eloquent's own attribute declares columns. One of the same short name from another
     * namespace says nothing about the model, so the column stays unknown.
     */
    public function test_a_fillable_attribute_from_another_namespace_is_not_read(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            'use App\Attributes\Fillable;',
            "#[Fillable(['subject', 'html'])]",
            '',
            'subject',
        );

        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining("'subject'", $result);
    }

    /**
     * An accessor's return type has to be Eloquent's own Attribute. One of the same short name
     * from another namespace makes the method an ordinary one, so the name stays unknown.
     */
    public function test_an_attribute_accessor_from_another_namespace_is_not_read(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            'use App\Casts\Attribute;',
            '',
            "protected function headline(): Attribute\n    {\n        return Attribute::make(get: fn (\$value) => strtoupper(\$value));\n    }",
            'headline',
        );

        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining("'headline'", $result);
    }

    /**
     * #[Hidden] and #[Visible] list relationships as well as columns, and #[Visible] has to list
     * every relationship the model serializes. So a name either lists says nothing about whether
     * it is a column, and a relationship from a trait the scan never read is still flagged.
     *
     * @dataProvider serializationAttributeProvider
     */
    #[DataProvider('serializationAttributeProvider')]
    public function test_a_relationship_listed_by_a_serialization_attribute_is_still_flagged(string $attribute): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Widget.php' => <<<PHP
<?php

namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Attributes\\{$attribute};
use Illuminate\\Database\\Eloquent\\Model;

#[{$attribute}(['id', 'gadgets'])]
class Widget extends Model
{
    use \\Vendor\\Pkg\\HasGadgets;
}
PHP,
            'app/Http/Controllers/WidgetController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Widget;

class WidgetController
{
    public function index()
    {
        $widgets = Widget::get();

        foreach ($widgets as $widget) {
            echo $widget->gadgets;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'gadgets'", $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function serializationAttributeProvider(): array
    {
        return [
            'Hidden' => ['Hidden'],
            'Visible' => ['Visible'],
        ];
    }

    /**
     * A class's own method shadows a trait's method of the same name, so a writer() relationship
     * the model declares is still one when a trait it uses declares writer() as an Attribute
     * accessor.
     */
    public function test_a_relationship_shadowing_a_trait_attribute_accessor_is_flagged(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/HasWriterLabel.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;

trait HasWriterLabel
{
    protected function writer(): Attribute
    {
        return Attribute::make(get: fn ($value) => strtoupper($value));
    }
}
PHP,
            'app/Models/Article.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Article extends Model
{
    use HasWriterLabel;
    use \Vendor\Pkg\HasThings;

    public function writer(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/ArticleController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Article;

class ArticleController
{
    public function index()
    {
        $articles = Article::get();

        foreach ($articles as $article) {
            echo $article->writer->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'writer'", $result);
    }

    /**
     * A #[Fillable] column and a relationship on the same model, read in the same loop: only the
     * relationship is flagged.
     */
    public function test_flags_only_the_relationship_beside_a_fillable_attribute_column(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Newsletter.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable(['subject', 'html'])]
class Newsletter extends Model
{
    use \Vendor\Pkg\HasThings;

    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/NewsletterController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Newsletter;

class NewsletterController
{
    public function index()
    {
        $newsletters = Newsletter::get();

        foreach ($newsletters as $newsletter) {
            echo $newsletter->subject;
            echo $newsletter->author->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'author'", $result);
    }

    /**
     * A get...Attribute() accessor only answers a property read. Calling the method of the same
     * name reaches the relationship directly, so the calls are still flagged.
     *
     * @dataProvider accessorBesideRelationshipProvider
     */
    #[DataProvider('accessorBesideRelationshipProvider')]
    public function test_a_relationship_called_as_a_method_is_flagged_beside_an_accessor(string $relation, string $accessor): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Member.php' => <<<PHP
<?php

namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Model;
use Illuminate\\Database\\Eloquent\\Relations\\HasOne;

class Member extends Model
{
    public function {$relation}(): HasOne
    {
        return \$this->hasOne(Address::class);
    }

    public function {$accessor}()
    {
        return 'x';
    }
}
PHP,
            'app/Http/Controllers/MemberController.php' => <<<PHP
<?php

namespace App\\Http\\Controllers;

use App\\Models\\Member;

class MemberController
{
    public function index()
    {
        \$members = Member::get();

        foreach (\$members as \$member) {
            echo \$member->{$relation}()->first();
            echo \$member->{$relation}()->count();
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertIssueCount(3, $result);
        $this->assertHasIssueContaining("\$member->{$relation}()->first()", $result);
        $this->assertHasIssueContaining("\$member->{$relation}()->count()", $result);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function accessorBesideRelationshipProvider(): array
    {
        return [
            'accessor of the same name' => ['author', 'getAuthorAttribute'],
            'accessor of a multi-word name' => ['primaryAddress', 'getPrimaryAddressAttribute'],
        ];
    }

    /**
     * Calling an Attribute accessor returns the Attribute, not a relationship, so the call is
     * not flagged on a model not read in full.
     */
    public function test_calling_an_attribute_accessor_is_not_flagged(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            'use Illuminate\Database\Eloquent\Casts\Attribute;',
            '',
            "protected function headline(): Attribute\n    {\n        return Attribute::make(get: fn (\$value) => strtoupper(\$value));\n    }",
            'headline()',
        );

        $this->assertSame([], $this->issueMessagesNaming('headline', $result));
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'author'", $result);
    }

    /**
     * Model reads a selected column before it looks for a relationship, and a name $fillable
     * lists is almost always a column, so a relationship of the same name is never lazy-loaded
     * through a property read.
     *
     * @dataProvider fillableColumnBesideRelationshipProvider
     */
    #[DataProvider('fillableColumnBesideRelationshipProvider')]
    public function test_a_fillable_column_beside_a_same_named_relationship_is_not_flagged(string $imports, string $attributes, string $body, string $column): void
    {
        $result = $this->analyzeModelReadInLoop($imports, $attributes, $body, "echo \$item->{$column};");

        $this->assertSame([], $this->issueMessagesNaming($column, $result));
    }

    /**
     * @return array<string, array{string, string, string, string}>
     */
    public static function fillableColumnBesideRelationshipProvider(): array
    {
        return [
            'fillable property' => [
                'use Illuminate\Database\Eloquent\Relations\BelongsTo;',
                '',
                "protected \$fillable = ['author'];\n\n    public function author(): BelongsTo { return \$this->belongsTo(User::class); }",
                'author',
            ],
            'Fillable attribute' => [
                "use Illuminate\\Database\\Eloquent\\Attributes\\Fillable;\nuse Illuminate\\Database\\Eloquent\\Relations\\BelongsTo;",
                "#[Fillable(['author'])]",
                'public function author(): BelongsTo { return $this->belongsTo(User::class); }',
                'author',
            ],
            'fillable property beside a summing method' => [
                '',
                '',
                "protected \$fillable = ['balance'];\n\n    public function balance() { return \$this->hasMany(Txn::class)->sum('amount'); }",
                'balance',
            ],
        ];
    }

    /**
     * A column never answers a method call, so a relationship called as a method is flagged even
     * when casts(), $attributes or $fillable also names it.
     *
     * @dataProvider columnBesideCalledRelationshipProvider
     */
    #[DataProvider('columnBesideCalledRelationshipProvider')]
    public function test_a_relationship_called_as_a_method_is_flagged_beside_a_column_of_its_name(string $declaration): void
    {
        $result = $this->analyzeModelReadInLoop(
            'use Illuminate\Database\Eloquent\Relations\BelongsToMany;',
            '',
            "{$declaration}\n\n    public function labels(): BelongsToMany { return \$this->belongsToMany(Label::class); }",
            'echo $item->labels()->count();',
        );

        $this->assertIssueCount(2, $result);
        $this->assertHasIssueContaining("'labels'", $result);
        $this->assertHasIssueContaining('$item->labels()->count()', $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function columnBesideCalledRelationshipProvider(): array
    {
        return [
            'casts()' => ["protected function casts(): array { return ['labels' => 'array']; }"],
            'attributes property' => ["protected \$attributes = ['labels' => '[]'];"],
            'fillable property' => ["protected \$fillable = ['labels'];"],
        ];
    }

    /**
     * A method declared to return a built-in type cannot be a relationship, so calling it is not
     * flagged on a model not read in full, with or without an accessor of its name.
     *
     * @dataProvider builtinReturnTypeMethodProvider
     */
    #[DataProvider('builtinReturnTypeMethodProvider')]
    public function test_calling_a_method_declared_to_return_a_builtin_type_is_not_flagged(string $body): void
    {
        $result = $this->analyzeAttributeDeclaredColumn('', '', $body, 'permalink()');

        $this->assertSame([], $this->issueMessagesNaming('permalink', $result));
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'author'", $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function builtinReturnTypeMethodProvider(): array
    {
        return [
            'with an accessor of its name' => ["public function permalink(): string { return '/x'; }\n\n    public function getPermalinkAttribute() { return '/x'; }"],
            'alone' => ["public function permalink(): string { return '/x'; }"],
            'nullable union' => ["public function permalink(): string|int|null { return '/x'; }"],
        ];
    }

    /**
     * Beside a method returning a built-in type, a relationship declared by return type and one
     * declared only by its body are both still flagged when called in the same loop.
     */
    public function test_relationships_beside_a_builtin_return_type_method_are_still_flagged(): void
    {
        $result = $this->analyzeModelReadInLoop(
            'use Illuminate\Database\Eloquent\Relations\HasMany;',
            '',
            "public function permalink(): string { return '/x'; }\n\n    public function gadgets(): HasMany { return \$this->hasMany(Gadget::class); }\n\n    public function parts() { return \$this->hasMany(Part::class); }",
            "echo \$item->permalink();\n            echo \$item->gadgets()->count();\n            echo \$item->parts()->count();",
        );

        $this->assertSame([], $this->issueMessagesNaming('permalink', $result));
        $this->assertHasIssueContaining('$item->gadgets()->count()', $result);
        $this->assertHasIssueContaining('$item->parts()->count()', $result);
    }

    /**
     * A column name settles a method call too, unless a relationship of that name is proven: an
     * untyped helper named like a column is not judged by its name.
     *
     * @dataProvider columnNamedHelperProvider
     */
    #[DataProvider('columnNamedHelperProvider')]
    public function test_calling_a_helper_named_like_a_column_is_not_flagged(string $declaration): void
    {
        $result = $this->analyzeModelReadInLoop(
            '',
            '',
            "{$declaration}\n\n    public function headline() { return strtoupper(\$this->attributes['headline'] ?? ''); }",
            'echo $item->headline();',
        );

        $this->assertSame([], $this->issueMessagesNaming('headline', $result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function columnNamedHelperProvider(): array
    {
        return [
            'fillable property' => ["protected \$fillable = ['headline'];"],
            'casts()' => ["protected function casts(): array { return ['headline' => 'string']; }"],
        ];
    }

    /**
     * A trait outside the scanned paths, used by the class, overrides a method the parent
     * declares, so the parent's declaration says nothing about the name and the relationship
     * the trait may hold is still flagged.
     *
     * @dataProvider parentMethodBehindUnscannedTraitProvider
     */
    #[DataProvider('parentMethodBehindUnscannedTraitProvider')]
    public function test_a_parent_method_behind_an_unscanned_trait_is_not_trusted(string $imports, string $method): void
    {
        $result = $this->analyzeBookExtendingBaseBook($imports, $method, 'use \Acme\HasWriter;');

        $this->assertCount(1, $this->issueMessagesNaming('author', $result));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function parentMethodBehindUnscannedTraitProvider(): array
    {
        return [
            'built-in return type' => ['', "public function author(): string { return 'x'; }"],
            'Attribute accessor' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                'protected function author(): Attribute { return Attribute::make(get: fn ($value) => $value); }',
            ],
        ];
    }

    /**
     * The control: a scanned trait that declares no author() leaves the parent's built-in
     * author() in force, so the read is not flagged.
     */
    public function test_a_parent_method_behind_a_scanned_trait_is_trusted(): void
    {
        $result = $this->analyzeBookExtendingBaseBook('', "public function author(): string { return 'x'; }", 'use HasLabels;', [
            'app/Models/HasLabels.php' => "<?php\n\nnamespace App\\Models;\n\ntrait HasLabels\n{\n    public function labelText(): string { return 'x'; }\n}\n",
        ]);

        $this->assertSame([], $this->issueMessagesNaming('author', $result));
    }

    /**
     * Book extends BaseBook, which declares $method, and uses $traitUse; a controller reads
     * $book->author in a loop.
     *
     * @param  array<string, string>  $extraFiles
     */
    private function analyzeBookExtendingBaseBook(string $imports, string $method, string $traitUse, array $extraFiles = []): ResultInterface
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/BaseBook.php' => "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n{$imports}\n\nabstract class BaseBook extends Model\n{\n    {$method}\n}\n",
            'app/Models/Book.php' => "<?php\n\nnamespace App\\Models;\n\nclass Book extends BaseBook\n{\n    {$traitUse}\n}\n",
            'app/Http/Controllers/BookController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Book;

class BookController
{
    public function index()
    {
        $books = Book::get();

        foreach ($books as $book) {
            echo $book->author;
        }
    }
}
PHP,
            ...$extraFiles,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    /**
     * A project with one Item model, which uses a trait outside the scanned paths so it is not
     * read in full, and a controller running $statements for each item in a loop.
     */
    private function analyzeModelReadInLoop(string $imports, string $attributes, string $body, string $statements): ResultInterface
    {
        $model = "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n{$imports}\n\n{$attributes}\nclass Item extends Model\n{\n    use \\Vendor\\Pkg\\HasThings;\n\n    {$body}\n}\n";

        $tempDir = $this->createTempDirectory([
            'app/Models/Item.php' => $model,
            'app/Http/Controllers/ItemController.php' => <<<PHP
<?php

namespace App\\Http\\Controllers;

use App\\Models\\Item;

class ItemController
{
    public function index()
    {
        \$items = Item::get();

        foreach (\$items as \$item) {
            {$statements}
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    /**
     * spatie/laravel-activitylog's LogsActivity declares one relationship, activities(), so a
     * model using it is still read in full and a column it does not declare as a method is
     * conclusively not a relationship.
     */
    public function test_a_model_using_logs_activity_is_read_in_full(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Newsletter.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Spatie\Activitylog\Traits\LogsActivity;

class Newsletter extends Model
{
    use LogsActivity;
}
PHP,
            'app/Http/Controllers/NewsletterController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Newsletter;

class NewsletterController
{
    public function index()
    {
        $newsletters = Newsletter::get();

        foreach ($newsletters as $newsletter) {
            echo $newsletter->subject;
            echo $newsletter->activities;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertSame([], $this->issueMessagesNaming('subject', $result));
        $this->assertIssueCount(1, $result);
        $this->assertHasIssueContaining("'activities'", $result);
    }

    /**
     * @return list<string>
     */
    private function issueMessagesNaming(string $name, ResultInterface $result): array
    {
        return array_values(array_filter(
            array_map(fn ($issue): string => $issue->message, $result->getIssues()),
            fn (string $message): bool => str_contains($message, "'{$name}'"),
        ));
    }

    /**
     * A project with a Newsletter model declaring $column through $attributes or $body, which
     * uses a trait outside the scanned paths so the model is not read in full, and a Post model
     * whose author() relationship is the control. One controller reads both in loops.
     */
    private function analyzeAttributeDeclaredColumn(string $imports, string $attributes, string $body, string $column): ResultInterface
    {
        $model = "<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Vendor\\Pkg\\HasThings;\n{$imports}\n\n{$attributes}\nclass Newsletter extends Model\n{\n    use HasThings;\n\n    {$body}\n}\n";

        $tempDir = $this->createTempDirectory([
            'app/Models/Newsletter.php' => $model,
            'app/Models/Post.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Post extends Model
{
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Http/Controllers/NewsletterController.php' => <<<PHP
<?php

namespace App\\Http\\Controllers;

use App\\Models\\Newsletter;
use App\\Models\\Post;

class NewsletterController
{
    public function index()
    {
        \$newsletters = Newsletter::get();

        foreach (\$newsletters as \$newsletter) {
            echo \$newsletter->{$column};
        }

        \$posts = Post::get();

        foreach (\$posts as \$post) {
            echo \$post->author;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        return $analyzer->analyze();
    }

    // -------------------------------------------------------------------------
    // Nested foreach over a relation
    // -------------------------------------------------------------------------

    /**
     * Shelf and Book models for the nested-loop tests: Shelf::books() is a hasMany naming
     * Book, and Book::publisher() is a belongsTo.
     *
     * @return array<string, string>
     */
    private function shelfAndBookModels(): array
    {
        return [
            'app/Models/Shelf.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Shelf extends Model
{
    public function books(): HasMany
    {
        return $this->hasMany(Book::class);
    }
}
PHP,
            'app/Models/Book.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Book extends Model
{
    public function publisher(): BelongsTo
    {
        return $this->belongsTo(Publisher::class);
    }
}
PHP,
        ];
    }

    /**
     * Relationship and line of each relationship finding, in report order.
     *
     * @return list<array{string, int|null}>
     */
    private function nestedShelfFindings(string $query): array
    {
        $controller = <<<PHP
<?php

namespace App\Http\Controllers;

use App\Models\Shelf;

class ShelfController
{
    public function index()
    {
        \$shelves = {$query};

        foreach (\$shelves as \$shelf) {
            foreach (\$shelf->books as \$book) {
                echo \$book->publisher->name;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            ...$this->shelfAndBookModels(),
            'app/Http/Controllers/ShelfController.php' => $controller,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $findings = [];
        foreach ($analyzer->analyze()->getIssues() as $issue) {
            $relationship = $issue->metadata['relationship'] ?? null;
            if (is_string($relationship)) {
                $findings[] = [$relationship, $issue->location?->line];
            }
        }

        return $findings;
    }

    /**
     * The inner foreach's subject is read once per outer iteration, so it belongs to the
     * outer loop. It used to be judged against the inner loop's variable, which it never
     * mentions, so neither level was reported.
     */
    public function test_nested_foreach_over_a_relation_flags_both_levels(): void
    {
        $this->assertSame([['books', 14], ['publisher', 15]], $this->nestedShelfFindings('Shelf::all()'));
    }

    public function test_nested_foreach_flags_the_inner_relation_when_only_the_outer_is_eager_loaded(): void
    {
        $this->assertSame([['publisher', 15]], $this->nestedShelfFindings("Shelf::with('books')->get()"));
    }

    public function test_nested_foreach_silent_when_the_dotted_path_is_eager_loaded(): void
    {
        $this->assertSame([], $this->nestedShelfFindings("Shelf::with('books.publisher')->get()"));
    }

    /**
     * A query in the inner foreach's subject runs once per outer iteration, and depends on
     * the outer loop's variable, not the inner one's.
     */
    public function test_query_in_a_nested_foreach_subject_is_checked_against_the_enclosing_loop(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Book;
use App\Models\Shelf;

class ShelfController
{
    public function index()
    {
        foreach (Shelf::all() as $shelf) {
            foreach (Book::where('shelf_id', $shelf->id)->get() as $book) {
                echo $book->title;
            }
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            ...$this->shelfAndBookModels(),
            'app/Http/Controllers/ShelfController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertHasIssueContaining('Book::where', $result);
    }

    /**
     * The other side of judging the subject in the enclosing loop: when that loop always
     * exits after the inner foreach, the subject's query runs once.
     */
    public function test_query_in_a_nested_foreach_subject_is_silent_when_the_enclosing_loop_exits_after_it(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Book;
use App\Models\Shelf;

class ShelfController
{
    public function index()
    {
        foreach (Shelf::all() as $shelf) {
            foreach (Book::where('shelf_id', $shelf->id)->get() as $book) {
                echo $book->title;
            }

            break;
        }
    }
}
PHP;

        $tempDir = $this->createTempDirectory([
            ...$this->shelfAndBookModels(),
            'app/Http/Controllers/ShelfController.php' => $code,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $this->assertPassed($analyzer->analyze());
    }

    /**
     * Every finding as `relationship:line`, or `query:line` for a query executed in a loop.
     *
     * @param  array<string, string>  $files
     * @return list<string>
     */
    private function findingLines(array $files): array
    {
        $tempDir = $this->createTempDirectory($files);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $findings = [];
        foreach ($analyzer->analyze()->getIssues() as $issue) {
            $relationship = $issue->metadata['relationship'] ?? null;
            $findings[] = (is_string($relationship) ? $relationship : 'query').':'.$issue->location?->line;
        }

        return $findings;
    }

    /**
     * A shelf query, a loop over its shelves and a loop over each shelf's books, with $inner
     * as the inner loop's body on line 8 (one line later when $query spans two). Shelf declares books() and curator(); Book declares
     * publisher() and shelf(). $models replaces or adds model files.
     *
     * @param  array<string, string>  $models
     * @return list<string>
     */
    private function shelfLoopFindings(string $query, string $inner, array $models = []): array
    {
        return $this->findingLines([
            'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(Book::class); } public function curator(){ return \$this->belongsTo(Curator::class); } }",
            'app/Models/Book.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Book extends Model { public function publisher(){ return \$this->belongsTo(Publisher::class); } public function shelf(){ return \$this->belongsTo(Shelf::class); } }",
            ...$models,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(\$config) {\n\$shelves = {$query};\nforeach (\$shelves as \$shelf) {\n foreach (\$shelf->books as \$book) {\n {$inner};\n }\n}\n} }",
        ]);
    }

    /**
     * A closure-keyed eager load constrains the nested query, and a with() inside it loads
     * the next level, so `books.publisher` is loaded as surely as the dotted spelling.
     */
    public function test_nested_eager_load_inside_a_closure_keyed_with_is_honoured(): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::with(['books' => fn (\$q) => \$q->with('publisher')])->get()",
            'echo $book->publisher->name',
        ));
    }

    public function test_nested_eager_load_inside_a_closure_keyed_load_is_honoured(): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::all();\n\$shelves->load(['books' => function (\$query) { \$query->where('open', true)->with(['publisher']); }])",
            'echo $book->publisher->name',
        ));
    }

    /**
     * A with() nested two closures deep loads its relation under the path of both keys,
     * not under the outer key alone.
     */
    public function test_doubly_nested_closure_eager_load_is_read_under_its_full_path(): void
    {
        $this->assertSame(['publisher:8'], $this->shelfLoopFindings(
            "Shelf::with(['books' => fn (\$q) => \$q->with(['shelf' => fn (\$s) => \$s->with('publisher')])])->get()",
            'echo $book->publisher->name',
        ));
    }

    /**
     * chaperone() inside the eager-load closure hydrates each book's inverse relation from
     * the shelf already in memory, so reading it runs no query.
     */
    public function test_chaperone_inside_a_closure_keyed_with_leaves_the_inverse_silent(): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::with(['books' => fn (\$q) => \$q->chaperone()])->get()",
            'echo $book->shelf->label',
        ));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function inverseRelationDeclarations(): array
    {
        return [
            'chaperone' => ['$this->hasMany(Book::class)->chaperone()'],
            'inverse with a name' => ["\$this->hasMany(Book::class)->inverse('shelf')"],
        ];
    }

    /**
     * A relation declared with chaperone() or inverse() hydrates the inverse on every
     * element, and which relation that is Laravel guesses from key names at runtime.
     *
     * @dataProvider inverseRelationDeclarations
     */
    #[DataProvider('inverseRelationDeclarations')]
    public function test_relation_declared_with_an_inverse_leaves_the_element_silent(string $declaration): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::with('books')->get()",
            'echo $book->shelf->label',
            ['app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return {$declaration}; } }"],
        ));
    }

    /**
     * The related model ships in a package the scan never reads, so its columns cannot be
     * told from its relations and the element stays untyped.
     */
    public function test_element_of_a_relation_to_an_unscanned_model_is_silent(): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::with('books')->get()",
            'echo $book->disk',
            ['app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Vendor\\Library\\Models\\Volume;\nclass Shelf extends Model { public function books(){ return \$this->morphMany(Volume::class, 'holder'); } }"],
        ));
    }

    public function test_element_of_a_relation_to_an_aliased_model_is_typed_by_the_model(): void
    {
        $this->assertSame([], $this->shelfLoopFindings(
            "Shelf::with('books')->get()",
            'echo $book->isbn',
            ['app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse App\\Models\\Book as Volume;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(Volume::class); } }"],
        ));
    }

    /**
     * The inner loop runs once per shelf, so a lazy relation of the shelf read inside it is
     * still one query per shelf.
     */
    public function test_relation_of_the_outer_loop_variable_read_in_the_inner_loop_is_flagged(): void
    {
        $this->assertSame(['curator:8'], $this->shelfLoopFindings("Shelf::with('books')->get()", 'echo $shelf->curator->name'));
    }

    public function test_relation_of_the_outer_loop_variable_read_in_the_inner_loop_honours_its_eager_loads(): void
    {
        $this->assertSame([], $this->shelfLoopFindings("Shelf::with(['books', 'curator'])->get()", 'echo $shelf->curator->name'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function earlierLoopsReusingTheName(): array
    {
        return [
            'relation subject' => ['$shelf = Shelf::with(\'books\')->find(1); foreach ($shelf->books as $item) { echo $item->isbn; }'],
            'variable subject' => ['$books = Book::with(\'shelf\')->get(); foreach ($books as $item) { echo $item->isbn; }'],
        ];
    }

    /**
     * A foreach rebinds its variable, so a type an earlier loop gave the same name says
     * nothing about what a later loop over an untyped subject holds.
     *
     * @dataProvider earlierLoopsReusingTheName
     */
    #[DataProvider('earlierLoopsReusingTheName')]
    public function test_loop_variable_type_does_not_leak_into_a_later_loop_reusing_the_name(string $earlierLoop): void
    {
        $this->assertSame([], $this->findingLines([
            'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(Book::class); } }",
            'app/Models/Book.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Book extends Model { public function publisher(){ return \$this->belongsTo(Publisher::class); } public function shelf(){ return \$this->belongsTo(Shelf::class); } }",
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Book;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(\$config) {\n{$earlierLoop}\nforeach (\$config->entries as \$item) {\n echo \$item->publisher;\n}\n} }",
        ]));
    }

    /**
     * Shelf and Book models plus a ShelfController whose index() body is $body, starting on
     * line 6. $models replaces or adds model files.
     *
     * @param  array<string, string>  $models
     * @return list<string>
     */
    private function shelfControllerFindings(string $body, array $models = []): array
    {
        return $this->findingLines([
            'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(Book::class); } }",
            'app/Models/Book.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Book extends Model { public function publisher(){ return \$this->belongsTo(Publisher::class); } }",
            ...$models,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Book;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(\$config) {\n{$body}\n} }",
        ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function collectionLoads(): array
    {
        return [
            'load' => ['load'],
            'loadMissing' => ['loadMissing'],
        ];
    }

    /**
     * Loading onto the relation's collection loads onto every element of it.
     *
     * @dataProvider collectionLoads
     */
    #[DataProvider('collectionLoads')]
    public function test_eager_load_on_the_relation_collection_is_honoured(string $method): void
    {
        $this->assertSame([], $this->shelfControllerFindings(
            "\$shelf = Shelf::with('books')->findOrFail(1);\n\$shelf->books->{$method}('publisher');\nforeach (\$shelf->books as \$book) { echo \$book->publisher->name; }",
        ));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function withWhereHasQueries(): array
    {
        return [
            'dotted path' => ["Shelf::withWhereHas('books.publisher')->get()"],
            'constraint closure' => ["Shelf::withWhereHas('books', fn (\$q) => \$q->with('publisher'))->get()"],
        ];
    }

    /**
     * withWhereHas() filters on the relation and eager-loads it through with().
     *
     * @dataProvider withWhereHasQueries
     */
    #[DataProvider('withWhereHasQueries')]
    public function test_with_where_has_is_read_as_an_eager_load(string $query): void
    {
        $this->assertSame([], $this->shelfLoopFindings($query, 'echo $book->publisher->name'));
    }

    /**
     * Laravel flattens `['books' => ['publisher']]` into `books` and `books.publisher`.
     */
    public function test_nested_array_eager_load_is_read_under_its_key(): void
    {
        $this->assertSame([], $this->shelfLoopFindings("Shelf::with(['books' => ['publisher']])->get()", 'echo $book->publisher->name'));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function partiallyReadRelatedModels(): array
    {
        return [
            'extends a package model' => [
                "<?php\nnamespace App\\Models;\nclass Tag extends \\Vendor\\Tags\\Tag {}",
                'echo $tag->pivot->note',
            ],
            'uses a package trait' => [
                "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Tag extends Model { use \\Vendor\\Pkg\\HasStuff; }",
                'echo $tag->colour',
            ],
        ];
    }

    /**
     * An element whose model the scan read only in part cannot have its columns told from
     * its relations, so it stays untyped rather than falling to the naming heuristic.
     *
     * @dataProvider partiallyReadRelatedModels
     */
    #[DataProvider('partiallyReadRelatedModels')]
    public function test_element_of_a_relation_to_a_partially_read_model_is_silent(string $tagModel, string $inner): void
    {
        $this->assertSame([], $this->shelfControllerFindings(
            "\$shelf = Shelf::with('tags')->findOrFail(1);\nforeach (\$shelf->tags as \$tag) { {$inner}; }",
            [
                'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function tags(){ return \$this->belongsToMany(Tag::class)->withPivot('note'); } }",
                'app/Models/Tag.php' => $tagModel,
            ],
        ));
    }

    /**
     * setRelation() puts a collection the scan knows nothing about in the relation's place,
     * so the relation is loaded and its elements cannot be judged.
     */
    public function test_set_relation_leaves_the_relation_loaded_and_its_elements_untyped(): void
    {
        $this->assertSame([], $this->shelfControllerFindings(
            "\$shelf = Shelf::findOrFail(1);\n\$shelf->setRelation('books', \$config->books);\nforeach (\$shelf->books as \$book) { echo \$book->publisher->name; }",
        ));
    }

    /**
     * A query in the inner loop that depends on the outer loop's variable still runs once
     * per inner iteration.
     */
    public function test_query_depending_on_the_outer_loop_variable_inside_the_inner_loop_is_flagged(): void
    {
        $this->assertSame(['query:8'], $this->shelfLoopFindings("Shelf::with('books')->get()", "echo Book::where('shelf_id', \$shelf->id)->count()"));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function queriesFollowedByAnExitFromEveryLoop(): array
    {
        return [
            'break 2 after a search in the inner loop' => ["foreach (Shelf::all() as \$shelf) {\nforeach (\$config->items as \$item) {\nif (\$item === \$config->wanted) {\n\$found = Book::where('shelf_id', \$shelf->id)->first();\nbreak 2;\n}\n}\n}"],
            'break 2 after a query in the inner foreach subject' => ["foreach (Shelf::all() as \$shelf) {\nforeach (\$config->groups as \$group) {\nforeach (Book::where('shelf_id', \$shelf->id)->get() as \$book) { echo \$book->title; }\nbreak 2;\n}\n}"],
            'break 1 in a single loop' => ["foreach (Shelf::all() as \$shelf) {\n\$book = Book::where('shelf_id', \$shelf->id)->first();\nbreak 1;\n}"],
        ];
    }

    /**
     * `break N` leaves the N innermost loops, so a query followed by a break out of every
     * enclosing loop runs at most once.
     *
     * @dataProvider queriesFollowedByAnExitFromEveryLoop
     */
    #[DataProvider('queriesFollowedByAnExitFromEveryLoop')]
    public function test_query_followed_by_a_break_out_of_every_loop_is_silent(string $body): void
    {
        $this->assertSame([], $this->shelfControllerFindings($body));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function relationWrites(): array
    {
        return [
            'assignment in a single loop' => ['$shelves = Shelf::all();', '$shelf->books = $config->books;'],
            'unset in a single loop' => ['$shelves = Shelf::all();', 'unset($shelf->books);'],
        ];
    }

    /**
     * Writing a relation property sets or drops it on the model in memory; only reading it
     * runs the lazy load.
     *
     * @dataProvider relationWrites
     */
    #[DataProvider('relationWrites')]
    public function test_writing_a_relation_property_in_a_loop_is_silent(string $query, string $write): void
    {
        $this->assertSame([], $this->shelfControllerFindings("{$query}\nforeach (\$shelves as \$shelf) { {$write} }"));
    }

    /**
     * A compound assignment reads the property before writing it, and `??=` reads it through
     * isset(), which loads a relation like any other read.
     */
    public function test_compound_assignment_to_a_relation_property_is_still_a_read(): void
    {
        $this->assertSame(['books:7'], $this->shelfControllerFindings("\$shelves = Shelf::all();\nforeach (\$shelves as \$shelf) { \$shelf->books ??= \$config->books; }"));
    }

    public function test_assigning_a_relation_property_of_the_inner_loop_element_is_silent(): void
    {
        $this->assertSame([], $this->shelfLoopFindings("Shelf::with('books')->get()", '$book->publisher = $config->publisher'));
    }

    /**
     * Auth::user() returns a model, but the chain is rooted at the facade, whose name says
     * nothing about the model a relation on the user returns.
     */
    public function test_relation_query_rooted_at_the_auth_facade_is_not_typed(): void
    {
        $this->assertSame([], $this->findingLines([
            'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model {}",
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Auth;\nclass ShelfController { public function index() {\n\$shelves = Auth::user()->shelves()->get();\nforeach (\$shelves as \$shelf) { echo \$shelf->subtitle; }\n} }",
        ]));
    }

    /**
     * @return array<string, array{string, list<string>}>
     */
    public static function breaksThroughASwitch(): array
    {
        $nested = static fn (string $key, string $break): string => "foreach (Shelf::all() as \$shelf) {\nswitch (\$config->mode) {\ncase 1:\nforeach (\$config->items as \$item) {\n\$b = Book::where('id', {$key})->first();\n{$break};\n}\n}\n}";

        return [
            'break 2 leaves the inner loop and the switch' => [$nested('$item->id', 'break 2'), ['query:10']],
            'break 2 with a query on the outer variable' => [$nested('$shelf->id', 'break 2'), ['query:10']],
            'break 3 leaves the outer loop too' => [$nested('$item->id', 'break 3'), []],
            'break inside a case leaves only the switch' => ["foreach (Shelf::all() as \$shelf) {\nswitch (\$config->mode) {\ncase 1:\n\$b = Book::where('shelf_id', \$shelf->id)->first();\nbreak;\n}\n}", ['query:9']],
        ];
    }

    /**
     * A switch is a level for `break N` as a loop is, so a break counts the loops among the
     * levels it leaves, not the levels themselves.
     *
     * @dataProvider breaksThroughASwitch
     *
     * @param  list<string>  $expected
     */
    #[DataProvider('breaksThroughASwitch')]
    public function test_break_counts_a_switch_as_a_level(string $body, array $expected): void
    {
        $this->assertSame($expected, $this->shelfControllerFindings($body));
    }

    public function test_batch_command_n_plus_one_is_downgraded(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class SyncCommand extends Command
{
    protected $signature = 'sync';

    public function handle(): int
    {
        User::query()->chunkById(500, function ($users) {
            foreach ($users as $user) {
                $profile = \App\Models\Profile::where('user_id', $user->id)->first();
                $this->info((string) $profile?->id);
            }
        });

        return 0;
    }
}
PHP;

        $tempDir = $this->createTempDirectory(['app/Console/Commands/SyncCommand.php' => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    /**
     * The downgrade belongs to the file, so a relationship the registry proves is graded the
     * same as a query in a command that eager-loads, rather than at the High a proven
     * relationship gets on the request path.
     */
    public function test_batch_command_relationship_access_is_downgraded(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => self::POST_WITH_AUTHOR_MODEL,
            'app/Console/Commands/DigestCommand.php' => <<<'PHP'
<?php

namespace App\Console\Commands;

use App\Models\Post;
use Illuminate\Console\Command;

class DigestCommand extends Command
{
    public function handle(): int
    {
        $posts = Post::with('comments')->get();

        foreach ($posts as $post) {
            $this->info($post->author->name);
        }

        return 0;
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertCount(1, $result->getIssues());
        $this->assertSame("Potential N+1 query: accessing 'author' inside loop", $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    /**
     * Any one of the bounded-iteration or eager-loading calls is enough, whether it is
     * written on an instance or statically on the model.
     *
     * @dataProvider boundedCommandCallProvider
     */
    #[DataProvider('boundedCommandCallProvider')]
    public function test_command_using_bounded_iteration_or_eager_loading_is_downgraded(string $call): void
    {
        $result = $this->analyzeLoopQueryIn('app/Console/Commands/SyncCommand.php', 'extends Command', $call);

        $this->assertCount(1, $result->getIssues());
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function boundedCommandCallProvider(): array
    {
        $cases = [];
        foreach (['chunk', 'chunkById', 'chunkByIdDesc', 'each', 'eachById', 'cursor', 'lazy', 'lazyById', 'lazyByIdDesc', 'with', 'load', 'loadMissing'] as $method) {
            $cases[$method] = ["\$builder->{$method}();"];
        }
        $cases['static with()'] = ["User::with('profile')->get();"];
        $cases['nullsafe load()'] = ['$user?->load(\'profile\');'];
        $cases['lowercase chunkbyid()'] = ['$builder->chunkbyid(100, fn () => null);'];

        return $cases;
    }

    /**
     * The downgrade needs both halves. A command that does no bounded iteration or eager
     * loading, or only names one in a string or a comment, and a class that uses chunkById()
     * but is not a command, all keep the request-path grade.
     *
     * @dataProvider notDowngradedProvider
     */
    #[DataProvider('notDowngradedProvider')]
    public function test_query_in_loop_stays_high_unless_a_command_bounds_its_iteration(string $path, string $extends, string $preamble): void
    {
        $result = $this->analyzeLoopQueryIn($path, $extends, $preamble);

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame("N+1 query: executing 'Profile::where()->...first()' inside loop", $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function notDowngradedProvider(): array
    {
        return [
            'command with no bounded call' => ['app/Console/Commands/SyncCommand.php', 'extends Command', "\$this->info('Syncing');"],
            'command naming chunk only in a string and a comment' => [
                'app/Console/Commands/SyncCommand.php',
                'extends Command',
                "// Switch to chunk() or ->chunkById() once this is slow.\n        \$this->info('with chunk() and cursor()');",
            ],
            'non-command class under app/Console' => ['app/Console/Support/UserSync.php', '', '$builder->chunkById(100, fn () => null);'],
            'request-path controller' => ['app/Http/Controllers/SyncController.php', '', '$builder->chunkById(100, fn () => null);'],
        ];
    }

    /**
     * The model's parent is outside the scanned paths, so nothing proves what sku is and only
     * the name decides it. A guess is reported, but not at the grade of a proven relationship.
     */
    public function test_relationship_access_decided_by_the_name_heuristic_is_downgraded(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Product.php' => <<<'PHP'
<?php

namespace App\Models;

class Product extends \Acme\Catalog\RecordBase {}
PHP,
            'app/Http/Controllers/ProductController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Product;

class ProductController
{
    public function index()
    {
        $products = Product::get();

        foreach ($products as $product) {
            echo $product->sku;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertWarning($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame("Potential N+1 query: accessing 'sku' inside loop", $result->getIssues()[0]->message);
        $this->assertSame(Severity::Medium, $result->getIssues()[0]->severity);
    }

    public function test_proven_relationship_access_on_the_request_path_stays_high(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => self::POST_WITH_AUTHOR_MODEL,
            'app/Http/Controllers/PostController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->author->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame("Potential N+1 query: accessing 'author' inside loop", $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * A chain is only as proven as its least proven link. The trait proves author, but the
     * model's parent is outside the scanned paths, so team is decided by its name alone.
     */
    public function test_relationship_chain_with_a_heuristic_link_is_downgraded(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasAuthor.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\User;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

trait HasAuthor
{
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Models/Post.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasAuthor;

class Post extends \Acme\Catalog\RecordBase
{
    use HasAuthor;
}
PHP,
            'app/Http/Controllers/PostController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->author->team;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $severities = [];
        foreach ($analyzer->analyze()->getIssues() as $issue) {
            $severities[$issue->message] = $issue->severity;
        }

        $this->assertSame([
            "Potential N+1 query: accessing 'author.team' inside loop" => Severity::Medium,
            "Potential N+1 query: accessing 'author' inside loop" => Severity::High,
        ], $severities);
    }

    /**
     * A chain's tail is read on the head relation's related model, not on the loop
     * variable's. Post declares a team() relation, but team here is read on the User that
     * author() returns, where it is a column. The analyzer does not record which model a
     * relation returns, so it cannot prove the tail and grades the chain as a guess. The
     * head's own finding is proven and stays High.
     */
    public function test_chain_tail_named_like_a_relation_on_the_loop_model_is_not_proven(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Post extends Model
{
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }
}
PHP,
            'app/Models/User.php' => <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $fillable = ['team'];
}
PHP,
            'app/Http/Controllers/PostController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->author->team;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $severities = [];
        foreach ($analyzer->analyze()->getIssues() as $issue) {
            $severities[$issue->message] = $issue->severity;
        }

        $this->assertSame([
            "Potential N+1 query: accessing 'author.team' inside loop" => Severity::Medium,
            "Potential N+1 query: accessing 'author' inside loop" => Severity::High,
        ], $severities);
    }

    /**
     * The registries know a model by the name its declaration gives it, so a model imported
     * under an alias has to be looked up by what the alias resolves to. Otherwise a relation
     * the model declares is missed and reported as a guess.
     *
     * @dataProvider importedModelProvider
     */
    #[DataProvider('importedModelProvider')]
    public function test_relationship_access_is_graded_by_the_class_an_import_names(string $import, string $class, Severity $expected): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => self::POST_WITH_AUTHOR_MODEL,
            'app/Http/Controllers/ArticleController.php' => <<<PHP
<?php

namespace App\\Http\\Controllers;

{$import}

class ArticleController
{
    public function index()
    {
        \$articles = {$class}::all();

        foreach (\$articles as \$article) {
            echo \$article->author->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertCount(1, $result->getIssues());
        $this->assertSame("Potential N+1 query: accessing 'author' inside loop", $result->getIssues()[0]->message);
        $this->assertSame($expected, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string, string, Severity}>
     */
    public static function importedModelProvider(): array
    {
        return [
            'scanned model imported under an alias' => ['use App\\Models\\Post as Article;', 'Article', Severity::High],
            'scanned model imported by its own name' => ['use App\\Models\\Post;', 'Post', Severity::High],
            'unscanned class imported under an alias' => ['use Vendor\\Blog\\Entry as Article;', 'Article', Severity::Medium],
        ];
    }

    /**
     * Findings are deduplicated by variable and relation name, so two methods reusing $item
     * report one finding. A guess about the first must not grade away what the registry
     * proves about the second: the kept finding takes the higher grade, at the line of the
     * first so its baseline hash is unchanged.
     */
    public function test_proven_finding_is_not_swallowed_by_an_earlier_guess_on_the_same_variable_name(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => self::POST_WITH_AUTHOR_MODEL,
            'app/Models/Activity.php' => <<<'PHP'
<?php

namespace App\Models;

class Activity extends \Acme\Audit\Entry {}
PHP,
            'app/Http/Controllers/FeedController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Activity;
use App\Models\Post;

class FeedController
{
    public function activity()
    {
        $items = Activity::latest()->get();
        foreach ($items as $item) {
            echo $item->author->name;
        }
    }

    public function posts()
    {
        $items = Post::latest()->get();
        foreach ($items as $item) {
            echo $item->author->name;
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $issue = $result->getIssues()[0];
        $this->assertSame("Potential N+1 query: accessing 'author' inside loop", $issue->message);
        $this->assertSame(Severity::High, $issue->severity);
        $this->assertSame(14, $issue->location?->line);
    }

    /**
     * Inside a model, self:: and static:: name that model, so a relation it declares is
     * proven there just as it is through the model's own name.
     *
     * @dataProvider selfReferenceProvider
     */
    #[DataProvider('selfReferenceProvider')]
    public function test_relationship_access_on_a_self_query_inside_the_model_is_proven(string $query): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Post.php' => <<<PHP
<?php

namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Model;
use Illuminate\\Database\\Eloquent\\Relations\\BelongsTo;

class Post extends Model
{
    public function author(): BelongsTo
    {
        return \$this->belongsTo(User::class);
    }

    public static function digest(): array
    {
        \$out = [];
        \$posts = {$query};
        foreach (\$posts as \$post) {
            \$out[] = \$post->author->name;
        }

        return \$out;
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $result = $analyzer->analyze();

        $this->assertFailed($result);
        $this->assertCount(1, $result->getIssues());
        $this->assertSame("Potential N+1 query: accessing 'author' inside loop", $result->getIssues()[0]->message);
        $this->assertSame(Severity::High, $result->getIssues()[0]->severity);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function selfReferenceProvider(): array
    {
        return [
            'self::query()' => ['self::query()->latest()->get()'],
            'static::all()' => ['static::all()'],
        ];
    }

    /**
     * A query run through a relation method is only as proven as that relation. reviews() is
     * decided by its name alone here, while author() is declared on the model.
     */
    public function test_relation_query_in_a_loop_is_graded_by_how_the_relation_was_decided(): void
    {
        $tempDir = $this->createTempDirectory([
            'app/Models/Concerns/HasAuthor.php' => <<<'PHP'
<?php

namespace App\Models\Concerns;

use App\Models\User;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

trait HasAuthor
{
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP,
            'app/Models/Post.php' => <<<'PHP'
<?php

namespace App\Models;

use App\Models\Concerns\HasAuthor;

class Post extends \Acme\Catalog\RecordBase
{
    use HasAuthor;
}
PHP,
            'app/Http/Controllers/PostController.php' => <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController
{
    public function index()
    {
        $posts = Post::all();

        foreach ($posts as $post) {
            echo $post->reviews()->count();
            echo $post->author()->first();
        }
    }
}
PHP,
        ]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['app']);

        $severities = [];
        foreach ($analyzer->analyze()->getIssues() as $issue) {
            if (array_key_exists('query', $issue->metadata)) {
                $severities[$issue->message] = $issue->severity;
            }
        }

        $this->assertSame([
            'N+1 query: executing \'$post->reviews()->count()\' inside loop' => Severity::Medium,
            'N+1 query: executing \'$post->author()->first()\' inside loop' => Severity::High,
        ], $severities);
    }

    private const POST_WITH_AUTHOR_MODEL = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Post extends Model
{
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
PHP;

    /**
     * One per-iteration query, `Profile::where()->...first()`, in a class at $path, after
     * $preamble.
     */
    private function analyzeLoopQueryIn(string $path, string $extends, string $preamble): ResultInterface
    {
        $code = <<<PHP
<?php

namespace App\\Fixture;

use App\\Models\\Profile;
use App\\Models\\User;
use Illuminate\\Console\\Command;

class Subject {$extends}
{
    public function handle(\$builder): int
    {
        {$preamble}

        \$users = User::all();

        foreach (\$users as \$user) {
            \$profile = Profile::where('user_id', \$user->id)->first();
        }

        return 0;
    }
}
PHP;

        $tempDir = $this->createTempDirectory([$path => $code]);

        $analyzer = $this->createAnalyzer();
        $analyzer->setBasePath($tempDir);
        $analyzer->setPaths(['.']);

        return $analyzer->analyze();
    }
}
