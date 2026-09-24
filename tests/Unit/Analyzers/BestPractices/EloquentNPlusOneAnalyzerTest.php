<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use PhpParser\NodeTraverser;
use ShieldCI\Analyzers\BestPractices\AccessorRegistry;
use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\Analyzers\BestPractices\ModelAttributesRegistry;
use ShieldCI\Analyzers\BestPractices\ModelScanResult;
use ShieldCI\Analyzers\BestPractices\NPlusOneVisitor;
use ShieldCI\Analyzers\BestPractices\RelationshipRegistry;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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
        $this->assertFailed($result);
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
        $this->assertFailed($result);
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
        // relationship). That used to make isActualOrProbableRelationship() fall through
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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

        $this->assertFailed($result);
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
}
